#!/usr/bin/env python3
"""
parse_pcaps.py — Extract per-handshake packet and byte counts from pcap files.

Requires: pyshark (wraps tshark)
Output  : results/csv/pcap_stats.csv
"""

import argparse
import re
import sys
from pathlib import Path

try:
    import pyshark
except ImportError:
    print("[error] pyshark not installed. Run: pip install pyshark", file=sys.stderr)
    sys.exit(1)

import pandas as pd

FILENAME_RE = re.compile(
    r"^(?P<protocol>tls|quic)_(?P<kem>.+?)_(?P<network>ideal|low_loss|medium_loss|high_loss)\.pcapng?$"
)

# TLS handshake message content types
TLS_HANDSHAKE_RECORDS = {
    "1": "ClientHello",
    "2": "ServerHello",
    "11": "Certificate",
    "15": "CertificateVerify",
    "20": "Finished",
    "8": "EncryptedExtensions",
}


def analyse_tls_pcap(filepath: Path) -> dict:
    """Analyse a TLS-over-TCP pcap and return per-handshake statistics."""
    cap = pyshark.FileCapture(
        str(filepath),
        display_filter="tls.handshake",
        only_summaries=False,
    )

    total_bytes = 0
    total_packets = 0
    msg_sizes: dict[str, int] = {}

    try:
        for pkt in cap:
            try:
                pkt_len = int(pkt.length)
                total_bytes += pkt_len
                total_packets += 1

                # Inspect TLS handshake layers
                if hasattr(pkt, "tls"):
                    hs_type = str(getattr(pkt.tls, "handshake_type", ""))
                    hs_len = int(getattr(pkt.tls, "handshake_length", 0))
                    name = TLS_HANDSHAKE_RECORDS.get(hs_type, f"type_{hs_type}")
                    msg_sizes[name] = msg_sizes.get(name, 0) + hs_len
            except Exception:
                continue
    finally:
        cap.close()

    result = {
        "total_bytes": total_bytes,
        "total_packets": total_packets,
    }
    result.update({f"msg_{k}_bytes": v for k, v in msg_sizes.items()})
    return result


def analyse_quic_pcap(filepath: Path) -> dict:
    """Analyse a QUIC-over-UDP pcap and return per-handshake statistics."""
    cap = pyshark.FileCapture(
        str(filepath),
        display_filter="quic",
        only_summaries=False,
    )

    total_bytes = 0
    total_packets = 0
    initial_pkts = 0
    handshake_pkts = 0

    try:
        for pkt in cap:
            try:
                pkt_len = int(pkt.length)
                total_bytes += pkt_len
                total_packets += 1

                if hasattr(pkt, "quic"):
                    # Long header types: Initial=0x00, 0-RTT=0x01, Handshake=0x02, Retry=0x03
                    quic_type = str(getattr(pkt.quic, "long_packet_type", ""))
                    if quic_type == "0":
                        initial_pkts += 1
                    elif quic_type == "2":
                        handshake_pkts += 1
            except Exception:
                continue
    finally:
        cap.close()

    return {
        "total_bytes": total_bytes,
        "total_packets": total_packets,
        "initial_packets": initial_pkts,
        "handshake_packets": handshake_pkts,
    }


def main():
    parser = argparse.ArgumentParser(description="Extract stats from pcap files")
    parser.add_argument(
        "--pcap-dir", default="results/raw", help="Directory with pcap files"
    )
    parser.add_argument("--output", default="results/csv/pcap_stats.csv")
    args = parser.parse_args()

    pcap_dir = Path(args.pcap_dir)
    pcap_files = sorted(pcap_dir.glob("**/*.pcap*"))

    if not pcap_files:
        print(f"[error] No pcap files found in {pcap_dir}", file=sys.stderr)
        sys.exit(1)

    rows = []
    for f in pcap_files:
        match = FILENAME_RE.match(f.name)
        if not match:
            continue

        protocol = match.group("protocol")
        kem = match.group("kem")
        network = match.group("network")

        print(f"  -> Analysing {f.name} ...", end=" ", flush=True)
        try:
            if protocol == "tls":
                stats = analyse_tls_pcap(f)
            else:
                stats = analyse_quic_pcap(f)

            row = {"protocol": protocol, "kem": kem, "network": network, **stats}
            rows.append(row)
            print(f"OK ({stats['total_packets']} pkts, {stats['total_bytes']} bytes)")
        except Exception as exc:
            print(f"FAILED: {exc}", file=sys.stderr)

    if not rows:
        print("[error] No pcap data extracted", file=sys.stderr)
        sys.exit(1)

    df = pd.DataFrame(rows)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"\n[info] Saved pcap stats -> {output_path}")


if __name__ == "__main__":
    main()
