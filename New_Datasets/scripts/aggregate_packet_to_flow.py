#!/usr/bin/env python3
"""Build endpoint/window flow observations from run-scoped packet CSVs.

Only completed, explicitly labeled runs are eligible. For each run, retain
traffic from the manifest's client/attacker to its target at the source host's
access switch. This avoids treating the same network packets observed on
multiple switches, or reverse-path replies, as independent model examples.
Raw packet and raw switch-flow files are never modified.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent
MANIFEST = ROOT / "experiments" / "run_manifest.csv"
LABELS = {"Normal", "Malicious_POST", "Port_Scan", "SYN_Flood"}


def protocol(value: object) -> str:
    text = str(value).strip().lower()
    if text.endswith(".0"):
        text = text[:-2]
    return {
        "6": "tcp", "17": "udp", "1": "icmp",
        "tcp": "tcp", "udp": "udp", "icmp": "icmp",
    }.get(text, "")


def flag(value: object, mask: int) -> int:
    try:
        return int(int(float(value)) & mask != 0)
    except (TypeError, ValueError):
        return 0


def load_host_switch_map() -> dict[str, int]:
    """Map endpoint IPv4 addresses to the DPID of their access switch."""
    mininet_dir = str(PROJECT_ROOT / "mininet")
    if mininet_dir not in sys.path:
        sys.path.insert(0, mininet_dir)
    try:
        from vlan_config_38host import HOSTS
    except Exception as exc:
        raise SystemExit(
            "cannot load mininet/vlan_config_38host.py; refusing to guess "
            f"source access switches: {exc}"
        ) from exc

    result: dict[str, int] = {}
    for host, spec in HOSTS.items():
        try:
            address = str(ipaddress.ip_interface(spec["ip"]).ip)
            switch = str(spec["switch"])
            if not switch.startswith("s"):
                raise ValueError("switch name must look like s1")
            dpid = int(switch[1:])
        except (KeyError, TypeError, ValueError) as exc:
            raise SystemExit(f"invalid 38-host inventory entry {host!r}: {exc}") from exc
        if address in result:
            raise SystemExit(f"duplicate host IP in topology inventory: {address}")
        result[address] = dpid
    if len(result) != 38:
        raise SystemExit(f"expected 38 endpoint addresses, got {len(result)}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--window-sec", type=float, default=5.0)
    args = parser.parse_args()
    if args.window_sec <= 0:
        raise SystemExit("--window-sec must be greater than zero")

    host_switch = load_host_switch_map()
    with MANIFEST.open(newline="", encoding="utf-8") as handle:
        manifest = {
            row["run_id"]: row
            for row in csv.DictReader(handle)
            if row.get("run_id")
        }

    frames = []
    for path in sorted(args.input_dir.glob("*.csv")):
        run_id = path.stem
        run = manifest.get(run_id)
        if run is None:
            raise SystemExit(f"{path.name}: run_id is not in run_manifest.csv")
        if run.get("status", "").strip().lower() != "completed":
            raise SystemExit(f"{run_id}: refusing non-completed run")

        label = run.get("label", "").strip()
        if label not in LABELS:
            raise SystemExit(f"{run_id}: missing or invalid label {label!r}")
        source_ip = run.get("attacker_ip", "").strip()
        target_ip = run.get("target_ip", "").strip()
        if not source_ip or not target_ip:
            raise SystemExit(f"{run_id}: manifest source/target IP is required")
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
            target_ip = str(ipaddress.ip_address(target_ip))
        except ValueError as exc:
            raise SystemExit(f"{run_id}: invalid manifest endpoint IP: {exc}") from exc
        source_dpid = host_switch.get(source_ip)
        if source_dpid is None:
            raise SystemExit(
                f"{run_id}: source {source_ip} is not a known 38-host endpoint"
            )

        df = pd.read_csv(path)
        if df.empty:
            raise SystemExit(f"{run_id}: packet file is empty")
        required = {"timestamp", "switch_dpid", "src_ip", "dst_ip", "protocol"}
        missing = sorted(required - set(df.columns))
        if missing:
            raise SystemExit(f"{run_id}: packet CSV missing columns: {missing}")
        for col in ("src_port", "dst_port", "packet_length", "tcp_flags"):
            if col not in df.columns:
                df[col] = ""

        df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
        df["switch_dpid"] = pd.to_numeric(df["switch_dpid"], errors="coerce")
        df["packet_length"] = pd.to_numeric(
            df["packet_length"], errors="coerce"
        ).fillna(0)
        df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce")
        df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
        df["protocol_name"] = df["protocol"].map(protocol)
        df["src_ip"] = df["src_ip"].fillna("").astype(str).str.strip()
        df["dst_ip"] = df["dst_ip"].fillna("").astype(str).str.strip()

        try:
            start = float(run.get("start_time", ""))
            end = float(run.get("end_time", ""))
        except (TypeError, ValueError):
            raise SystemExit(f"{run_id}: invalid manifest run timestamps")
        if start <= 0 or end < start:
            raise SystemExit(f"{run_id}: invalid manifest run time interval")
        df = df[
            (df["timestamp"] >= start)
            & (df["timestamp"] <= end + args.window_sec)
        ].copy()

        # Keep one canonical vantage point per unidirectional endpoint flow:
        # the access switch attached to the source endpoint, not every transit
        # switch. Keep only the experiment's source-to-target direction so
        # response packets cannot masquerade as destination-port scans.
        df = df[
            (df["src_ip"] == source_ip)
            & (df["dst_ip"] == target_ip)
            & (df["switch_dpid"] == source_dpid)
        ].copy()
        df = df[df["protocol_name"].isin(["tcp", "udp", "icmp"])].copy()
        if df.empty:
            raise SystemExit(
                f"{run_id}: no source-to-target IPv4 packets at source access "
                f"switch s{source_dpid}; run is not eligible for flow assembly"
            )

        df["window_start"] = (df["timestamp"] // args.window_sec) * args.window_sec
        df["syn"] = df["tcp_flags"].map(lambda value: flag(value, 0x02))
        df["ack"] = df["tcp_flags"].map(lambda value: flag(value, 0x10))
        df["rst"] = df["tcp_flags"].map(lambda value: flag(value, 0x04))
        df["fin"] = df["tcp_flags"].map(lambda value: flag(value, 0x01))

        group_cols = ["window_start", "src_ip", "dst_ip", "protocol_name"]
        rows = []
        for key, group in df.groupby(group_cols, dropna=False, sort=True):
            window, src, dst, proto = key
            packets = len(group)
            byte_count = float(group["packet_length"].sum())
            first = float(group["timestamp"].min())
            last = float(group["timestamp"].max())
            duration = max(last - first, 0.001)
            src_ports = sorted(
                {int(value) for value in group["src_port"].dropna() if value > 0}
            )
            dst_ports = sorted(
                {int(value) for value in group["dst_port"].dropna() if value > 0}
            )
            syn = int(group["syn"].sum())
            ack = int(group["ack"].sum())
            rst = int(group["rst"].sum())
            rows.append({
                "timestamp": last,
                "switch_dpid": source_dpid,
                "src_ip": src,
                "dst_ip": dst,
                "src_port": src_ports[0] if len(src_ports) == 1 else 0,
                "dst_port": dst_ports[0] if len(dst_ports) == 1 else 0,
                "protocol": proto,
                "priority": 0,
                "packet_count": packets,
                "byte_count": byte_count,
                "packet_rate": packets / duration,
                "byte_rate": byte_count / duration,
                "duration_sec": duration,
                "avg_packet_size": byte_count / max(packets, 1),
                "syn_count": syn,
                "ack_count": ack,
                "rst_count": rst,
                "fin_count": int(group["fin"].sum()),
                "syn_ack_ratio": syn / max(ack, 1),
                "rst_ratio": rst / max(packets, 1),
                "unique_dst_ports": len(dst_ports),
                "failed_connection_count": max(syn - ack, 0),
                "tcp_fraction": float(proto == "tcp"),
                "udp_fraction": float(proto == "udp"),
                "icmp_fraction": float(proto == "icmp"),
            })

        out = pd.DataFrame(rows)
        out.insert(0, "observation_id", [
            f"{run_id}_flow_{index:08d}" for index in range(len(out))
        ])
        out.insert(0, "run_id", run_id)
        out["label"] = label
        out["label_status"] = "matched"
        frames.append(out)
        print(
            f"{run_id}: label={label} src={source_ip} dst={target_ip} "
            f"edge=s{source_dpid} packet_rows={len(df)} flow_windows={len(out)}"
        )

    if not frames:
        raise SystemExit("no eligible completed runs found")
    result = pd.concat(frames, ignore_index=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.output, index=False)
    print(
        f"wrote {len(result)} canonical flow windows from "
        f"{result['run_id'].nunique()} runs to {args.output}"
    )
    print(result.groupby(["run_id", "label"]).size().to_string())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
