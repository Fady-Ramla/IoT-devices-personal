#!/usr/bin/env python3
"""Aggregate per-run packet CSVs into endpoint/window flow observations.

This mirrors TrafficMonitorMerged's PacketIn fallback: one observation per
run, time window, switch, IPv4 unicast source, destination, and protocol.
It intentionally does not group by ephemeral source port, so SYN floods and
port scans retain meaningful rate and port-diversity features.
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments" / "run_manifest.csv"
LABELS = {"Normal", "Malicious_POST", "Port_Scan", "SYN_Flood"}


def protocol(value: object) -> str:
    text = str(value).strip().lower()
    if text.endswith(".0"):
        text = text[:-2]
    return {"6": "tcp", "17": "udp", "1": "icmp", "tcp": "tcp", "udp": "udp", "icmp": "icmp"}.get(text, "")


def flag(value: object, mask: int) -> int:
    try:
        return int(int(float(value)) & mask != 0)
    except (TypeError, ValueError):
        return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--input-dir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--window-sec", type=float, default=5.0)
    args = p.parse_args()
    with MANIFEST.open(newline="", encoding="utf-8") as f:
        manifest = {r["run_id"]: r for r in csv.DictReader(f) if r.get("run_id")}
    frames = []
    for path in sorted(args.input_dir.glob("*.csv")):
        run_id = path.stem
        if run_id not in manifest:
            raise SystemExit(f"{path.name}: run_id is not in run_manifest.csv")
        df = pd.read_csv(path)
        if df.empty:
            continue
        for col in ["timestamp", "switch_dpid", "src_port", "dst_port", "packet_length"]:
            if col not in df:
                df[col] = 0
        for col in ["src_ip", "dst_ip"]:
            if col not in df:
                df[col] = ""
        df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
        try:
            start = float(manifest[run_id].get("start_time", ""))
            end = float(manifest[run_id].get("end_time", ""))
        except (TypeError, ValueError):
            start, end = 0.0, 0.0
        if start > 0 and end >= start:
            df = df[(df["timestamp"] >= start) & (df["timestamp"] <= end + args.window_sec)].copy()
        if df.empty:
            continue
        df["packet_length"] = pd.to_numeric(df["packet_length"], errors="coerce").fillna(0)
        df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce")
        df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
        df["protocol_name"] = df["protocol"].map(protocol)
        valid = df["src_ip"].astype(str).str.contains(r"^\d+\.\d+\.\d+\.\d+$") & df["dst_ip"].astype(str).str.contains(r"^\d+\.\d+\.\d+\.\d+$")
        valid &= ~df["dst_ip"].astype(str).str.startswith(("224.", "239."))
        valid &= df["protocol_name"].isin(["tcp", "udp", "icmp"])
        df = df[valid].copy()
        if df.empty:
            continue
        df["window_start"] = (df["timestamp"] // args.window_sec) * args.window_sec
        df["syn"] = df.get("tcp_flags", 0).map(lambda x: flag(x, 0x02))
        df["ack"] = df.get("tcp_flags", 0).map(lambda x: flag(x, 0x10))
        df["rst"] = df.get("tcp_flags", 0).map(lambda x: flag(x, 0x04))
        df["fin"] = df.get("tcp_flags", 0).map(lambda x: flag(x, 0x01))
        group_cols = ["window_start", "switch_dpid", "src_ip", "dst_ip", "protocol_name"]
        rows = []
        for key, g in df.groupby(group_cols, dropna=False, sort=True):
            window, dpid, src_ip, dst_ip, proto = key
            packets = len(g)
            bytes_total = float(g["packet_length"].sum())
            first = float(g["timestamp"].min())
            last = float(g["timestamp"].max())
            duration = max(last - first, 0.001)
            src_ports = sorted({int(x) for x in g["src_port"].dropna() if x > 0})
            dst_ports = sorted({int(x) for x in g["dst_port"].dropna() if x > 0})
            syn = int(g["syn"].sum())
            ack = int(g["ack"].sum())
            rst = int(g["rst"].sum())
            rows.append({
                "timestamp": last, "switch_dpid": dpid, "src_ip": src_ip, "dst_ip": dst_ip,
                # 0 means multiple/unspecified ports in a window; it is an
                # explicit value so CSV parsing cannot create NaN.
                "src_port": src_ports[0] if len(src_ports) == 1 else 0,
                "dst_port": dst_ports[0] if len(dst_ports) == 1 else 0,
                "protocol": proto, "priority": 0, "packet_count": packets,
                "byte_count": bytes_total, "packet_rate": packets / duration,
                "byte_rate": bytes_total / duration, "duration_sec": duration,
                "avg_packet_size": bytes_total / max(packets, 1), "syn_count": syn,
                "ack_count": ack, "rst_count": rst, "fin_count": int(g["fin"].sum()),
                "syn_ack_ratio": syn / max(ack, 1), "rst_ratio": rst / max(packets, 1),
                "unique_dst_ports": len(dst_ports), "failed_connection_count": max(syn - ack, 0),
                "tcp_fraction": float(proto == "tcp"), "udp_fraction": float(proto == "udp"),
                "icmp_fraction": float(proto == "icmp"),
            })
        out = pd.DataFrame(rows)
        out.insert(0, "observation_id", [f"{run_id}_{i:08d}" for i in range(len(out))])
        out.insert(0, "run_id", run_id)
        label = manifest[run_id].get("label") or "Normal"
        if label not in LABELS:
            raise SystemExit(f"{run_id}: invalid label {label!r}")
        out["label"] = label
        out["label_status"] = "matched"
        frames.append(out)
    if not frames:
        raise SystemExit("no valid IPv4 TCP/UDP/ICMP packet rows found")
    result = pd.concat(frames, ignore_index=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.output, index=False)
    print(f"wrote {len(result)} window-flow rows from {result['run_id'].nunique()} runs to {args.output}")
    print(result.groupby(["run_id", "label"]).size().to_string())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
