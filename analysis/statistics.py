#!/usr/bin/env python3
"""
statistics.py — Statistical analysis of handshake latency data.

Mirrors the statistical methodology from the article:
  - Mean, Standard Deviation, Coefficient of Variation (CV)
  - IQR-based outlier identification
  - Shapiro-Wilk normality test
  - Levene's homogeneity-of-variance test
  - Welch's t-test for pairwise comparison
  - Cohen's d effect size

Generates:
  results/csv/statistics_summary.csv
  results/csv/pairwise_tests.csv
  results/csv/tls_vs_quic.csv
"""

from __future__ import annotations

import argparse
import sys
from itertools import combinations
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from scipy import stats as scipy_stats

# ── Core statistics ──────────────────────────────────────────────────────────


def compute_stats(data: np.ndarray) -> dict[str, Any]:
    """
    Full statistical profile for a latency sample.
    Returns a dict of statistics matching the article's Table 5.
    """
    n = len(data)
    mean = float(np.mean(data))
    std = float(np.std(data, ddof=1))
    cv = (std / mean * 100.0) if mean > 0.0 else float("nan")

    # Compute each percentile individually so each value is a plain Python float
    # (avoids Pyright false-positives when indexing into a numpy array result).
    q1 = float(np.percentile(data, 25.0))
    median = float(np.percentile(data, 50.0))
    q3 = float(np.percentile(data, 75.0))
    iqr = q3 - q1

    # IQR-based outlier identification (Tukey's 1.5 × IQR fence)
    lo = q1 - 1.5 * iqr
    hi = q3 + 1.5 * iqr
    outliers = data[(data < lo) | (data > hi)]
    n_outliers = int(len(outliers))

    # Normality — Shapiro-Wilk (scipy caps at 5000 observations)
    sample = data[:5000] if n > 5000 else data
    sw_stat, sw_p = scipy_stats.shapiro(sample)
    is_normal = bool(float(sw_p) > 0.05)

    return {
        "n": n,
        "mean_us": round(mean, 3),
        "std_us": round(std, 3),
        "cv_pct": round(cv, 2),
        "median_us": round(median, 3),
        "q1_us": round(q1, 3),
        "q3_us": round(q3, 3),
        "iqr_us": round(iqr, 3),
        "n_outliers": n_outliers,
        "outlier_pct": round(n_outliers / n * 100.0, 2),
        "sw_stat": round(float(sw_stat), 6),
        "sw_p": round(float(sw_p), 6),
        "is_normal": is_normal,
    }


def compare_groups(
    name_a: str,
    data_a: np.ndarray,
    name_b: str,
    data_b: np.ndarray,
) -> dict[str, Any]:
    """
    Pairwise comparison using Levene's test + Welch's t-test.
    Returns a dict with test statistics and significance flags.
    """
    # Levene's test — homogeneity of variance
    # Unpack as a tuple so the types are unambiguous to static checkers.
    levene_result = scipy_stats.levene(data_a, data_b)
    levene_stat = float(levene_result[0])  # type: ignore[arg-type]
    levene_p = float(levene_result[1])  # type: ignore[arg-type]
    equal_var = levene_p > 0.05

    # Welch's t-test — does not assume equal variances
    welch_result = scipy_stats.ttest_ind(data_a, data_b, equal_var=False)
    welch_stat = float(welch_result[0])  # type: ignore[arg-type]
    welch_p = float(welch_result[1])  # type: ignore[arg-type]

    mean_a: float = float(np.mean(data_a))
    mean_b: float = float(np.mean(data_b))
    mean_diff = mean_a - mean_b
    mean_diff_pct = (mean_diff / mean_b * 100.0) if mean_b != 0.0 else float("nan")

    # Cohen's d — pooled standard deviation effect size
    pooled_std = float(
        np.sqrt((float(np.var(data_a, ddof=1)) + float(np.var(data_b, ddof=1))) / 2.0)
    )
    cohens_d = (mean_diff / pooled_std) if pooled_std > 0.0 else float("nan")

    return {
        "group_a": name_a,
        "group_b": name_b,
        "mean_a_us": round(mean_a, 3),
        "mean_b_us": round(mean_b, 3),
        "mean_diff_us": round(mean_diff, 3),
        "mean_diff_pct": round(mean_diff_pct, 2),
        "levene_stat": round(levene_stat, 6),
        "levene_p": round(levene_p, 6),
        "equal_variances": equal_var,
        "welch_stat": round(welch_stat, 6),
        "welch_p": round(welch_p, 6),
        "significant": welch_p < 0.05,
        "cohens_d": round(float(cohens_d), 4),
    }


# ── Main analysis ────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Statistical analysis of PQC handshake latency data"
    )
    parser.add_argument("--input", default="results/csv/combined_results.csv")
    parser.add_argument("--out-dir", default="results/csv")
    parser.add_argument(
        "--alpha",
        type=float,
        default=0.05,
        help="Significance level for hypothesis tests",
    )
    parser.add_argument(
        "--protocol", default=None, help="Filter to a single protocol: tls | quic"
    )
    parser.add_argument(
        "--network", default=None, help="Filter to a single network condition"
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[error] Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    df: pd.DataFrame = pd.read_csv(input_path)
    print(f"[info] Loaded {len(df)} rows from {input_path}")

    if args.protocol:
        df = df.loc[df["protocol"] == args.protocol].copy()
    if args.network:
        df = df.loc[df["network"] == args.network].copy()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── 1. Per-group descriptive statistics ──────────────────────────────────
    group_keys = ["protocol", "kem", "kem_type", "security_level", "network"]
    stat_rows: list[dict[str, Any]] = []

    for group_key_val, group_df in df.groupby(group_keys):
        # group_key_val is a tuple when grouping by multiple columns
        key_values: list[Any] = list(group_key_val)  # type: ignore[arg-type]
        latency_arr: np.ndarray = group_df["latency_us"].dropna().to_numpy(dtype=float)
        data = latency_arr
        if len(data) < 10:
            continue
        row: dict[str, Any] = dict(zip(group_keys, key_values))
        row.update(compute_stats(data))
        stat_rows.append(row)

    stats_df = pd.DataFrame(stat_rows)
    stats_path = out_dir / "statistics_summary.csv"
    stats_df.to_csv(stats_path, index=False)
    print(f"[info] Saved statistics summary -> {stats_path}  ({len(stats_df)} groups)")

    # ── 2. Pairwise KEM comparisons (within same protocol × network) ─────────
    pair_rows: list[dict[str, Any]] = []

    for pair_key_val, pair_grp in df.groupby(["protocol", "network"]):
        pair_keys: list[str] = [str(v) for v in pair_key_val]  # type: ignore[union-attr]
        proto_label = pair_keys[0]
        network_label = pair_keys[1]

        kems: list[str] = sorted(pair_grp["kem"].unique().tolist())
        for kem_a, kem_b in combinations(kems, 2):
            da: np.ndarray = np.asarray(
                pair_grp.loc[pair_grp["kem"] == kem_a, "latency_us"].dropna(),
                dtype=float,
            )
            db: np.ndarray = np.asarray(
                pair_grp.loc[pair_grp["kem"] == kem_b, "latency_us"].dropna(),
                dtype=float,
            )
            if len(da) < 5 or len(db) < 5:
                continue
            pair_row = compare_groups(kem_a, da, kem_b, db)
            pair_row["protocol"] = proto_label
            pair_row["network"] = network_label
            pair_rows.append(pair_row)

    if pair_rows:
        pairs_df = pd.DataFrame(pair_rows)
        pairs_path = out_dir / "pairwise_tests.csv"
        pairs_df.to_csv(pairs_path, index=False)
        print(f"[info] Saved pairwise tests -> {pairs_path}  ({len(pairs_df)} pairs)")

    # ── 3. TLS vs. QUIC head-to-head per KEM × network ───────────────────────
    h2h_rows: list[dict[str, Any]] = []

    for h2h_key_val, h2h_grp in df.groupby(["kem", "network"]):
        h2h_keys: list[str] = [str(v) for v in h2h_key_val]  # type: ignore[union-attr]
        kem_label = h2h_keys[0]
        network_label = h2h_keys[1]

        tls_data: np.ndarray = np.asarray(
            h2h_grp.loc[h2h_grp["protocol"] == "tls", "latency_us"].dropna(),
            dtype=float,
        )
        quic_data: np.ndarray = np.asarray(
            h2h_grp.loc[h2h_grp["protocol"] == "quic", "latency_us"].dropna(),
            dtype=float,
        )
        if len(tls_data) < 5 or len(quic_data) < 5:
            continue

        h2h_row = compare_groups(
            f"tls/{kem_label}",
            tls_data,
            f"quic/{kem_label}",
            quic_data,
        )
        h2h_row["kem"] = kem_label
        h2h_row["network"] = network_label
        h2h_rows.append(h2h_row)

    if h2h_rows:
        h2h_df = pd.DataFrame(h2h_rows)
        h2h_path = out_dir / "tls_vs_quic.csv"
        h2h_df.to_csv(h2h_path, index=False)
        print(
            f"[info] Saved TLS-vs-QUIC comparison -> {h2h_path}  ({len(h2h_df)} rows)"
        )

    # ── 4. Console summary (ideal network only) ───────────────────────────────
    if stats_df.empty:
        print("[warn] No statistics computed — check input data.")
        return

    print(
        "\n── Mean Handshake Latency (us) — ideal network ────────────────────────────"
    )
    ideal_mask = stats_df["network"] == "ideal"
    ideal_cols = ["protocol", "kem", "kem_type", "security_level", "mean_us", "cv_pct"]
    ideal_stats = stats_df.loc[ideal_mask, ideal_cols].sort_values(
        by=["protocol", "kem_type", "mean_us"]
    )
    print(ideal_stats.to_string(index=False))


if __name__ == "__main__":
    main()
