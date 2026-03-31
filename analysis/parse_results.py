#!/usr/bin/env python3
"""
parse_results.py — Parse raw timing log files into a unified CSV dataset.

Input : results/raw/<protocol>_<kem>_<network>.log (CSV: run,latency_us,timestamp_us)
Output: results/csv/combined_results.csv
"""

import argparse
import os
import re
import sys
from pathlib import Path

import pandas as pd

# ── KEM classification ───────────────────────────────────────────────────────
TRADITIONAL_KEMS = {
    "p256",
    "secp256r1",
    "x25519",
    "p384",
    "secp384r1",
    "x448",
    "p521",
    "secp521r1",
}

HYBRID_KEMS = {
    "x25519_mlkem512",
    "secp256r1_mlkem512",
    "p256_mlkem512",
    "x25519_mlkem768",
    "secp384r1_mlkem768",
    "p384_mlkem768",
    "x448_mlkem768",
    "x25519_mlkem1024",
    "secp521r1_mlkem1024",
    "p521_mlkem1024",
}

PQ_KEMS = {
    "mlkem512",
    "mlkem768",
    "mlkem1024",
    "hqc128",
    "hqc192",
    "hqc256",
}

SECURITY_LEVEL_MAP = {
    # Traditional
    "p256": "I",
    "secp256r1": "I",
    "x25519": "I",
    "p384": "III",
    "secp384r1": "III",
    "x448": "III",
    "p521": "V",
    "secp521r1": "V",
    # Hybrid
    "x25519_mlkem512": "I",
    "secp256r1_mlkem512": "I",
    "p256_mlkem512": "I",
    "x25519_mlkem768": "III",
    "secp384r1_mlkem768": "III",
    "p384_mlkem768": "III",
    "x448_mlkem768": "III",
    "x25519_mlkem1024": "V",
    "secp521r1_mlkem1024": "V",
    "p521_mlkem1024": "V",
    # Post-quantum
    "mlkem512": "I",
    "hqc128": "I",
    "mlkem768": "III",
    "hqc192": "III",
    "mlkem1024": "V",
    "hqc256": "V",
}


def classify_kem(kem: str) -> str:
    kem_lower = kem.lower()
    if kem_lower in HYBRID_KEMS:
        return "hybrid"
    if kem_lower in PQ_KEMS:
        return "post_quantum"
    return "traditional"


def get_security_level(kem: str) -> str:
    return SECURITY_LEVEL_MAP.get(kem.lower(), "unknown")


# ── Filename parser ──────────────────────────────────────────────────────────
# Expected filename pattern: <protocol>_<kem_group>_<network_condition>.log
# Example: tls_x25519_mlkem768_medium_loss.log
FILENAME_RE = re.compile(
    r"^(?P<protocol>tls|quic)_(?P<kem>.+?)_(?P<network>ideal|low_loss|medium_loss|high_loss)\.log$"
)


def parse_log_file(filepath: Path) -> pd.DataFrame | None:
    """Parse a single timing log file into a DataFrame."""
    match = FILENAME_RE.match(filepath.name)
    if not match:
        print(f"[warn] Skipping unrecognised file: {filepath.name}", file=sys.stderr)
        return None

    protocol = match.group("protocol")
    kem = match.group("kem")
    network = match.group("network")

    try:
        df = pd.read_csv(filepath)
        if not {"run", "latency_us"}.issubset(df.columns):
            print(f"[warn] Missing columns in {filepath.name}", file=sys.stderr)
            return None
    except Exception as exc:
        print(f"[error] Cannot read {filepath}: {exc}", file=sys.stderr)
        return None

    df["protocol"] = protocol
    df["kem"] = kem
    df["kem_type"] = classify_kem(kem)
    df["security_level"] = get_security_level(kem)
    df["network"] = network
    df["source_file"] = filepath.name

    return df


def main():
    parser = argparse.ArgumentParser(
        description="Parse raw timing logs into combined CSV"
    )
    parser.add_argument(
        "--raw-dir", default="results/raw", help="Directory with .log files"
    )
    parser.add_argument("--output", default="results/csv/combined_results.csv")
    parser.add_argument(
        "--remove-outliers",
        action="store_true",
        help="Remove IQR-based outliers before saving",
    )
    args = parser.parse_args()

    raw_dir = Path(args.raw_dir)
    if not raw_dir.exists():
        print(f"[error] Raw dir not found: {raw_dir}", file=sys.stderr)
        sys.exit(1)

    log_files = sorted(raw_dir.glob("*.log"))
    if not log_files:
        # Also search one level deep (timestamped sub-directories)
        log_files = sorted(raw_dir.glob("**/*.log"))

    if not log_files:
        print(f"[error] No .log files found in {raw_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"[info] Found {len(log_files)} log files")

    frames = []
    for f in log_files:
        df = parse_log_file(f)
        if df is not None:
            frames.append(df)
            print(f"  \u2713  {f.name:60s}  ({len(df)} rows)")

    if not frames:
        print("[error] No valid data parsed", file=sys.stderr)
        sys.exit(1)

    combined = pd.concat(frames, ignore_index=True)

    if args.remove_outliers:
        before = len(combined)

        def remove_iqr(group):
            q1, q3 = group["latency_us"].quantile([0.25, 0.75])
            iqr = q3 - q1
            lo, hi = q1 - 1.5 * iqr, q3 + 1.5 * iqr
            return group[(group["latency_us"] >= lo) & (group["latency_us"] <= hi)]

        combined = combined.groupby(
            ["protocol", "kem", "network"], group_keys=False
        ).apply(remove_iqr)
        after = len(combined)
        print(
            f"[info] Outlier removal: {before} \u2192 {after} rows ({before - after} removed)"
        )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(output_path, index=False)
    print(f"[info] Saved combined dataset \u2192 {output_path}  ({len(combined)} rows)")

    # Summary
    print(
        "\n\u2500\u2500 Dataset summary \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
    )
    summary = (
        combined.groupby(["protocol", "kem_type", "security_level", "network"])[
            "latency_us"
        ]
        .agg(["count", "mean", "std"])
        .round(2)
    )
    print(summary.to_string())


if __name__ == "__main__":
    main()
