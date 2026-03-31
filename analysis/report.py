#!/usr/bin/env python3
"""
report.py — Generate a Markdown summary report from analysis CSVs.

Output: results/report.md
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

NETWORK_LABELS = {
    "ideal": "Ideal (0% loss, 0ms delay)",
    "low_loss": "Low loss (0.1%, 20ms)",
    "medium_loss": "Medium loss (1%, 50ms)",
    "high_loss": "High loss (5%, 100ms)",
}


def md_table(df: pd.DataFrame, cols: list[str] | None = None) -> str:
    """Format a DataFrame as a Markdown table."""
    if cols:
        df = df[cols]
    lines = [
        "| " + " | ".join(str(c) for c in df.columns) + " |",
        "|" + "|".join(["---"] * len(df.columns)) + "|",
    ]
    for _, row in df.iterrows():
        lines.append("| " + " | ".join(str(v) for v in row.values) + " |")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate Markdown report")
    parser.add_argument("--stats", default="results/csv/statistics_summary.csv")
    parser.add_argument("--h2h", default="results/csv/tls_vs_quic.csv")
    parser.add_argument("--pcap", default="results/csv/pcap_stats.csv")
    parser.add_argument("--output", default="results/report.md")
    args = parser.parse_args()

    report_lines = [
        f"# PQC TLS/QUIC Handshake Evaluation Report",
        f"",
        f"> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"",
        f"---",
        f"",
    ]

    # -- 1. Summary statistics per condition ---------------------------------
    if Path(args.stats).exists():
        stats = pd.read_csv(args.stats)
        report_lines += [
            "## 1. Handshake Latency Summary",
            "",
            "### 1.1 Ideal Network Conditions",
            "",
        ]
        ideal = stats[stats["network"] == "ideal"][
            [
                "protocol",
                "kem",
                "kem_type",
                "security_level",
                "mean_us",
                "std_us",
                "cv_pct",
                "n",
            ]
        ].sort_values(["protocol", "kem_type", "mean_us"])
        ideal.columns = [
            "Protocol",
            "KEM",
            "Type",
            "Level",
            "Mean (us)",
            "Std (us)",
            "CV (%)",
            "N",
        ]
        report_lines += [md_table(ideal), "", "---", ""]

        for net in ["low_loss", "medium_loss", "high_loss"]:
            net_df = stats[stats["network"] == net][
                ["protocol", "kem", "mean_us", "cv_pct"]
            ].sort_values(["protocol", "mean_us"])
            if net_df.empty:
                continue
            report_lines += [
                f"### 1.{['low_loss', 'medium_loss', 'high_loss'].index(net) + 2} "
                f"{NETWORK_LABELS.get(net, net)}",
                "",
                md_table(net_df, ["protocol", "kem", "mean_us", "cv_pct"]),
                "",
                "---",
                "",
            ]

    # -- 2. TLS vs QUIC ------------------------------------------------------
    if Path(args.h2h).exists():
        h2h = pd.read_csv(args.h2h)
        report_lines += [
            "## 2. TLS vs. QUIC Comparison",
            "",
            "Welch's t-test (alpha = 0.05). `significant=True` means the difference is statistically significant.",
            "",
        ]
        ideal_h2h = h2h[h2h["network"] == "ideal"][
            [
                "kem",
                "mean_a_us",
                "mean_b_us",
                "mean_diff_pct",
                "welch_p",
                "significant",
                "cohens_d",
            ]
        ]
        ideal_h2h.columns = [
            "KEM",
            "TLS Mean (us)",
            "QUIC Mean (us)",
            "QUIC Advantage (%)",
            "Welch p",
            "Significant",
            "Cohen's d",
        ]
        report_lines += [md_table(ideal_h2h), "", "---", ""]

    # -- 3. Bandwidth overhead ------------------------------------------------
    if Path(args.pcap).exists():
        pcap = pd.read_csv(args.pcap)
        if not pcap.empty:
            report_lines += [
                "## 3. Bandwidth Overhead (per handshake)",
                "",
            ]
            bw_df = pcap[
                ["protocol", "kem", "network", "total_bytes", "total_packets"]
            ].copy()
            bw_df.columns = [
                "Protocol",
                "KEM",
                "Network",
                "Total Bytes",
                "Total Packets",
            ]
            report_lines += [md_table(bw_df), "", "---", ""]

    report_lines += [
        "## 4. Key Observations",
        "",
        "- **Hybrid KEMs** incur the highest latency and bandwidth due to carrying two key shares.",
        "- **Pure post-quantum KEMs** (ML-KEM) offer moderate overhead with quantum security.",
        "- **QUIC consistently outperforms TLS** in lossy networks due to integrated transport.",
        "",
        "*End of report.*",
        "",
    ]

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(report_lines))
    print(f"[info] Report saved -> {output_path}")


if __name__ == "__main__":
    main()
