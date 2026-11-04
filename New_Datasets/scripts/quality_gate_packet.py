#!/usr/bin/env python3
"""Packet-only run quality gate.

Application-route/provenance checks are intentionally excluded. Those belong to
an application telemetry gate and must not invalidate packet-only labels.
Raw files and the manifest are read-only.
"""
from __future__ import annotations
import argparse, csv, json
from collections import Counter
from pathlib import Path

ERROR_PATTERNS = (
    "curl: (28)", "connection timeout", "connection refused",
    "http error 4", "http error 5", "traceback", "unhandled",
    "command failed",
)
LABELS = {"Normal", "Port_Scan", "SYN_Flood", "Malicious_POST"}


def args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", required=True)
    p.add_argument("--packet-dir", required=True)
    p.add_argument("--output-csv", required=True)
    p.add_argument("--output-json", required=True)
    p.add_argument("--min-scan-ports", type=int, default=10)
    return p.parse_args()


def error_in(notes):
    text = str(notes or "").lower()
    return next((x for x in ERROR_PATTERNS if x in text), "")


def packet_stats(path):
    if not path.exists():
        return {"packet_file_exists": False, "packet_rows": 0, "tcp_rows": 0,
                "unique_dst_ports": 0, "unique_src_ips": 0,
                "unique_dst_ips": 0, "syn_flags": 0, "rst_flags": 0,
                "protocols": ""}
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    protocols = Counter(str(r.get("protocol", "")).strip().lower() for r in rows)
    dst_ports = {str(r.get("dst_port", "")).strip() for r in rows
                 if str(r.get("dst_port", "")).strip() not in {"", "0", "nan"}}
    src_ips = {str(r.get("src_ip", "")).strip() for r in rows if r.get("src_ip")}
    dst_ips = {str(r.get("dst_ip", "")).strip() for r in rows if r.get("dst_ip")}
    tcp = syn = rst = 0
    for r in rows:
        proto = str(r.get("protocol", "")).strip().lower()
        if proto in {"6", "6.0", "tcp"}:
            tcp += 1
        flags = str(r.get("tcp_flags", "")).strip()
        syn += flags in {"2", "2.0"}
        rst += flags in {"4", "4.0"}
    return {"packet_file_exists": True, "packet_rows": len(rows),
            "tcp_rows": tcp, "unique_dst_ports": len(dst_ports),
            "unique_src_ips": len(src_ips), "unique_dst_ips": len(dst_ips),
            "syn_flags": syn, "rst_flags": rst,
            "protocols": ";".join(f"{k}:{v}" for k, v in sorted(protocols.items()))}


def evaluate(row, s, min_scan_ports):
    label = str(row.get("label", "")).strip()
    reasons = []
    warnings = []
    err = error_in(row.get("notes", ""))
    if not row.get("run_id", "").strip(): reasons.append("missing_run_id")
    if label not in LABELS: reasons.append("invalid_label")
    if str(row.get("status", "")).strip().lower() != "completed": reasons.append("status_not_completed")
    if err: reasons.append(f"execution_error:{err}")
    if not s["packet_file_exists"]: reasons.append("missing_packet_file")
    if int(s["packet_rows"]) == 0: reasons.append("empty_packet_file")

    if label == "Normal":
        if err: reasons.append("normal_control_failed")
        elif int(s["packet_rows"]) < 10: reasons.append("normal_low_visibility")
    elif label == "Port_Scan":
        if str(row.get("attack_type", "")).strip().lower() != "port_scan":
            reasons.append("attack_type_mismatch")
        if int(s["unique_dst_ports"]) < min_scan_ports:
            reasons.append("insufficient_scan_port_visibility")
        # Do not reject packet runs solely because application-level scan
        # completion was not guaranteed. Preserve this as a warning.
        try:
            meta = json.loads(row.get("notes", ""))
            op = meta.get("operator_notes", {}) if isinstance(meta, dict) else {}
            if isinstance(op, str): op = json.loads(op)
            if isinstance(op, dict) and op.get("full_scan_guaranteed") is False:
                warnings.append("full_scan_not_guaranteed")
        except (ValueError, TypeError):
            pass
    elif label == "SYN_Flood":
        if int(s["tcp_rows"]) == 0: reasons.append("missing_tcp_telemetry")
        if int(s["syn_flags"]) == 0: reasons.append("missing_syn_activity")
    elif label == "Malicious_POST":
        # Route/body/HTTP response evidence is application-gate scope, not
        # packet-gate scope. Packet labels are accepted when packet evidence
        # and execution metadata pass the packet gate.
        pass

    decision = "accepted" if not reasons else "rejected"
    return decision, reasons, warnings


def main():
    a = args()
    with Path(a.manifest).open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    out = []
    for row in rows:
        s = packet_stats(Path(a.packet_dir) / f"{row.get('run_id', '').strip()}.csv")
        decision, reasons, warnings = evaluate(row, s, a.min_scan_ports)
        out.append({"run_id": row.get("run_id", ""), "label": row.get("label", ""),
                    "attack_type": row.get("attack_type", ""),
                    "status": row.get("status", ""), "decision": decision,
                    "reasons": ";".join(reasons), "warnings": ";".join(warnings), **s})
    csv_path, json_path = Path(a.output_csv), Path(a.output_json)
    csv_path.parent.mkdir(parents=True, exist_ok=True); json_path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(out[0]) if out else ["run_id", "decision", "reasons"]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(out)
    counts = Counter(x["decision"] for x in out)
    summary = {"manifest": a.manifest, "packet_dir": a.packet_dir,
               "min_scan_ports": a.min_scan_ports, "runs": len(out),
               "decisions": dict(sorted(counts.items())),
               "by_label": {label: dict(sorted(Counter(x["decision"] for x in out if x["label"] == label).items()))
                            for label in sorted(LABELS)},
               "report_csv": str(csv_path)}
    with json_path.open("w", encoding="utf-8") as f: json.dump(summary, f, indent=2); f.write("\n")
    print(json.dumps(summary, indent=2))

if __name__ == "__main__": main()
