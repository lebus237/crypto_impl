#!/usr/bin/env python3
"""
plot_results.py — Generate all figures for the evaluation report.

Figures produced:
  1. bar_ideal_latency.png     — Mean latency by KEM, both protocols, ideal network
  2. box_latency_per_kem.png   — Latency distribution per KEM group
  3. line_loss_impact.png      — Latency vs. packet-loss % for key KEMs
  4. bar_tls_vs_quic.png       — TLS vs. QUIC comparison per KEM
  5. heatmap_penalty.png       — PQC overhead heatmap (relative to classical)
  6. bar_bandwidth.png         — Bandwidth overhead per KEM (from pcap data)
"""

import argparse
import sys
from pathlib import Path

import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns

# ── Styling ──────────────────────────────────────────────────────────────────
PALETTE = {
    "traditional": "#2196F3",  # Blue
    "hybrid": "#FF9800",  # Orange
    "post_quantum": "#4CAF50",  # Green
}
PROTOCOL_STYLES = {
    "tls": {"linestyle": "-", "marker": "o"},
    "quic": {"linestyle": "--", "marker": "s"},
}
NETWORK_ORDER = ["ideal", "low_loss", "medium_loss", "high_loss"]
NETWORK_LABELS = {
    "ideal": "Ideal (0% loss)",
    "low_loss": "Low (0.1%)",
    "medium_loss": "Medium (1%)",
    "high_loss": "High (5%)",
}
LEVEL_ORDER = ["I", "III", "V"]

sns.set_theme(style="whitegrid", font_scale=1.1)
plt.rcParams.update({"figure.dpi": 150, "savefig.bbox": "tight"})


# ── Helpers ──────────────────────────────────────────────────────────────────


def load_data(results_csv: str, stats_csv: str | None = None):
    df = pd.read_csv(results_csv)
    stats = pd.read_csv(stats_csv) if stats_csv and Path(stats_csv).exists() else None
    return df, stats


def short_kem_label(kem: str) -> str:
    """Produce a concise x-axis label from a KEM name."""
    replacements = {
        "secp256r1": "p256",
        "secp384r1": "p384",
        "secp521r1": "p521",
        "mlkem": "ML-KEM",
        "hqc": "HQC",
        "_": "+",
    }
    label = kem
    for old, new in replacements.items():
        label = label.replace(old, new)
    return label.upper()


# ── Figure 1: Bar chart — mean latency by KEM (ideal network) ────────────────


def plot_ideal_latency(df: pd.DataFrame, out_dir: Path):
    ideal = df[df["network"] == "ideal"]
    summary = (
        ideal.groupby(["protocol", "kem", "kem_type", "security_level"])["latency_us"]
        .agg(mean="mean", sem=lambda x: x.std() / np.sqrt(len(x)))
        .reset_index()
    )

    fig, axes = plt.subplots(1, 3, figsize=(18, 6), sharey=False)
    fig.suptitle(
        "Mean TLS Handshake Latency (Ideal Network)", fontsize=14, fontweight="bold"
    )

    for ax, level in zip(axes, LEVEL_ORDER):
        sub = summary[summary["security_level"] == level].sort_values("mean")
        if sub.empty:
            ax.set_title(f"Level {level}")
            continue

        x = np.arange(len(sub))
        width = 0.35
        tls_mask = sub["protocol"] == "tls"
        quic_mask = sub["protocol"] == "quic"

        # Interleave by KEM, one bar per protocol
        grouped = sub.groupby("kem")
        kems = sorted(grouped.groups.keys())
        x_pos = np.arange(len(kems))

        for i, kem in enumerate(kems):
            grp = grouped.get_group(kem)
            colors = [
                PALETTE.get(
                    grp[grp["protocol"] == p]["kem_type"].values[0]
                    if len(grp[grp["protocol"] == p]) > 0
                    else "traditional",
                    "grey",
                )
                for p in ["tls", "quic"]
            ]
            for j, (proto, offset) in enumerate(
                [("tls", -width / 2), ("quic", width / 2)]
            ):
                row = grp[grp["protocol"] == proto]
                if row.empty:
                    continue
                ax.bar(
                    x_pos[i] + offset,
                    row["mean"].values[0] / 1000,
                    width,
                    yerr=row["sem"].values[0] / 1000,
                    color=colors[j],
                    alpha=0.85 if proto == "tls" else 0.6,
                    edgecolor="black",
                    linewidth=0.5,
                    label=proto if i == 0 else "",
                )

        ax.set_title(f"NIST Level {level}", fontweight="bold")
        ax.set_xticks(x_pos)
        ax.set_xticklabels([short_kem_label(k) for k in kems], rotation=35, ha="right")
        ax.set_ylabel("Mean Latency (ms)")
        ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.1f"))
        if level == LEVEL_ORDER[0]:
            ax.legend(title="Protocol")

    plt.tight_layout()
    path = out_dir / "bar_ideal_latency.png"
    fig.savefig(path)
    plt.close(fig)
    print(f"  ✓  {path.name}")


# ── Figure 2: Box plots — latency distribution ───────────────────────────────


def plot_box_distributions(df: pd.DataFrame, out_dir: Path):
    for protocol in ["tls", "quic"]:
        sub = df[(df["protocol"] == protocol) & (df["network"] == "ideal")].copy()
        if sub.empty:
            continue
        sub["latency_ms"] = sub["latency_us"] / 1000
        sub["label"] = sub["kem"].apply(short_kem_label)

        order = sub.groupby("label")["latency_ms"].median().sort_values().index.tolist()

        fig, ax = plt.subplots(figsize=(max(12, len(order) * 0.9), 6))
        kem_types = sub.set_index("label")["kem_type"].to_dict()
        palette = {
            k: PALETTE.get(kem_types.get(k, "traditional"), "grey") for k in order
        }

        sns.boxplot(
            data=sub,
            x="label",
            y="latency_ms",
            order=order,
            palette=palette,
            flierprops={"markersize": 2, "alpha": 0.3},
            ax=ax,
        )
        ax.set_xlabel("KEM Configuration")
        ax.set_ylabel("Handshake Latency (ms)")
        ax.set_title(
            f"{protocol.upper()} Handshake Latency Distribution (Ideal Network)",
            fontweight="bold",
        )
        plt.xticks(rotation=40, ha="right")

        # Legend patches
        from matplotlib.patches import Patch

        legend_elements = [
            Patch(facecolor=c, label=t.replace("_", " ").title())
            for t, c in PALETTE.items()
        ]
        ax.legend(handles=legend_elements, title="KEM Type")

        plt.tight_layout()
        path = out_dir / f"box_latency_{protocol}.png"
        fig.savefig(path)
        plt.close(fig)
        print(f"  ✓  {path.name}")


# ── Figure 3: Line chart — latency vs. network loss ─────────────────────────


def plot_loss_impact(df: pd.DataFrame, out_dir: Path, top_kems: int = 6):
    """Plot mean latency vs. network condition for key KEM configurations."""
    # Select representative KEMs (one per type per level I)
    level_i = df[df["security_level"] == "I"]
    kems = (
        level_i.groupby(["kem", "kem_type"])["latency_us"]
        .mean()
        .reset_index()
        .sort_values(["kem_type", "latency_us"])
        .groupby("kem_type")
        .head(2)["kem"]
        .unique()
    )

    sub = df[df["kem"].isin(kems)].copy()
    summary = (
        sub.groupby(["protocol", "kem", "kem_type", "network"])["latency_us"]
        .mean()
        .reset_index()
    )
    summary["latency_ms"] = summary["latency_us"] / 1000
    summary["network_order"] = summary["network"].map(
        {n: i for i, n in enumerate(NETWORK_ORDER)}
    )
    summary = summary.sort_values("network_order")

    fig, axes = plt.subplots(1, 2, figsize=(14, 6), sharey=False)
    fig.suptitle(
        "Handshake Latency vs. Network Condition", fontsize=13, fontweight="bold"
    )

    for ax, protocol in zip(axes, ["tls", "quic"]):
        pdata = summary[summary["protocol"] == protocol]
        for _, grp in pdata.groupby("kem"):
            kem_type = grp["kem_type"].iloc[0]
            color = PALETTE.get(kem_type, "grey")
            label = short_kem_label(grp["kem"].iloc[0])
            ax.plot(
                grp["network_order"],
                grp["latency_ms"],
                label=label,
                color=color,
                **PROTOCOL_STYLES[protocol],
            )

        ax.set_title(protocol.upper(), fontweight="bold")
        ax.set_xticks(range(len(NETWORK_ORDER)))
        ax.set_xticklabels(
            [NETWORK_LABELS[n] for n in NETWORK_ORDER], rotation=20, ha="right"
        )
        ax.set_ylabel("Mean Latency (ms)")
        ax.legend(title="KEM", fontsize=9)

    plt.tight_layout()
    path = out_dir / "line_loss_impact.png"
    fig.savefig(path)
    plt.close(fig)
    print(f"  ✓  {path.name}")


# ── Figure 4: TLS vs QUIC comparison bar chart ───────────────────────────────


def plot_tls_vs_quic(df: pd.DataFrame, out_dir: Path):
    ideal = df[df["network"] == "ideal"]
    summary = (
        ideal.groupby(["protocol", "kem", "kem_type"])["latency_us"]
        .mean()
        .reset_index()
    )

    pivot = summary.pivot_table(
        index=["kem", "kem_type"], columns="protocol", values="latency_us"
    ).reset_index()
    pivot = pivot.dropna(subset=["tls", "quic"])
    pivot["quic_advantage_pct"] = (pivot["tls"] - pivot["quic"]) / pivot["tls"] * 100
    pivot = pivot.sort_values(["kem_type", "quic_advantage_pct"])

    fig, ax = plt.subplots(figsize=(14, 6))
    x = np.arange(len(pivot))
    w = 0.4
    colors = [PALETTE.get(t, "grey") for t in pivot["kem_type"]]

    ax.bar(x - w / 2, pivot["tls"] / 1000, w, label="TLS", alpha=0.9, color=colors)
    ax.bar(
        x + w / 2,
        pivot["quic"] / 1000,
        w,
        label="QUIC",
        alpha=0.6,
        color=colors,
        hatch="//",
    )

    ax.set_xticks(x)
    ax.set_xticklabels(
        [short_kem_label(k) for k in pivot["kem"]], rotation=40, ha="right"
    )
    ax.set_ylabel("Mean Handshake Latency (ms)")
    ax.set_title("TLS vs. QUIC — Ideal Network", fontweight="bold")
    ax.legend()

    plt.tight_layout()
    path = out_dir / "bar_tls_vs_quic.png"
    fig.savefig(path)
    plt.close(fig)
    print(f"  ✓  {path.name}")


# ── Figure 5: Overhead heatmap ───────────────────────────────────────────────


def plot_overhead_heatmap(df: pd.DataFrame, out_dir: Path):
    ideal = df[(df["network"] == "ideal")]
    mean_df = ideal.groupby(["protocol", "kem"])["latency_us"].mean().reset_index()

    # Baseline: p256 or x25519 for each protocol
    baseline_kems = ["p256", "secp256r1", "x25519"]

    rows = []
    for proto in ["tls", "quic"]:
        proto_df = mean_df[mean_df["protocol"] == proto]
        baseline = proto_df[proto_df["kem"].isin(baseline_kems)]["latency_us"].min()
        if pd.isna(baseline) or baseline == 0:
            continue
        for _, row in proto_df.iterrows():
            rows.append(
                {
                    "protocol": proto,
                    "kem": short_kem_label(row["kem"]),
                    "overhead_x": row["latency_us"] / baseline,
                }
            )

    if not rows:
        return

    heat_df = pd.DataFrame(rows)
    pivot = heat_df.pivot(index="kem", columns="protocol", values="overhead_x")

    fig, ax = plt.subplots(figsize=(6, max(8, len(pivot) * 0.5)))
    sns.heatmap(
        pivot,
        annot=True,
        fmt=".2f",
        cmap="YlOrRd",
        linewidths=0.5,
        ax=ax,
        cbar_kws={"label": "Overhead (×)"},
    )
    ax.set_title("Relative Latency Overhead\nvs. P-256 baseline", fontweight="bold")
    ax.set_xlabel("Protocol")
    ax.set_ylabel("KEM Configuration")
    plt.tight_layout()
    path = out_dir / "heatmap_overhead.png"
    fig.savefig(path)
    plt.close(fig)
    print(f"  ✓  {path.name}")


# ── Main ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Generate evaluation plots")
    parser.add_argument("--input", default="results/csv/combined_results.csv")
    parser.add_argument("--stats", default="results/csv/statistics_summary.csv")
    parser.add_argument("--out-dir", default="results/plots")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[error] Input not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df, stats = load_data(args.input, args.stats)
    print(f"[info] Loaded {len(df)} rows.  Generating plots → {out_dir}/")

    plot_ideal_latency(df, out_dir)
    plot_box_distributions(df, out_dir)
    plot_loss_impact(df, out_dir)
    plot_tls_vs_quic(df, out_dir)
    plot_overhead_heatmap(df, out_dir)

    print(f"\n[done] All plots saved to {out_dir}/")


if __name__ == "__main__":
    main()
