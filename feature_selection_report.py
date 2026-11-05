"""
feature_selection_report.py
---------------------------
Read-Only Feature Selection Report.

Produces:
    - KEEP / REVIEW / DROP per feature
    - Redundancy groups
    - SYN Flood candidate features
    - Online availability check

Does NOT modify ML_FINAL.
Does NOT create training data.
"""

import os
import time
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import GroupShuffleSplit


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(
    os.environ.get("IOT_BASE_DIR", Path.home() / "IoT-devices")
)

PACKET_FILE = (
    BASE_DIR / "ML_FINAL" / "labeled_packet_features_ML.csv"
)

FLOW_FILE = (
    BASE_DIR / "ML_FINAL" / "labeled_traffic_features_ML.csv"
)

REPORT_DIR = BASE_DIR / "feature_selection"
REPORT_DIR.mkdir(exist_ok=True)

REPORT_MD = REPORT_DIR / "feature_selection_report.md"
REPORT_CSV = REPORT_DIR / "feature_selection_summary.csv"


# ============================================================
# CONFIG
# ============================================================

LABELS = ["normal", "syn_flood", "port_scan", "malicious_post"]

NON_FEATURE_COLS = {
    "timestamp",
    "run_id",
    "label",
}

IDENTIFIER_COLS = {
    "src_mac", "dst_mac",
    "src_ip", "dst_ip",
    "switch",
}

RANDOM_STATE = 42
RF_TREES = 100
TEST_SIZE = 0.20
CORR_THRESHOLD = 0.90
NORMAL_GROUP_SIZE = 5000

# Features confirmed to be available in TrafficMonitor
# (verified manually from traffic_monitor_merged.py)
ONLINE_AVAILABLE = {
    "src_port", "dst_port", "ip_proto", "ttl",
    "tcp", "udp", "icmp", "arp",
    "http", "https", "dns", "ssh", "telnet", "smtp",
    "syn_flag_number", "ack_flag_number",
    "fin_flag_number", "rst_flag_number", "psh_flag_number",
    "packet_length", "payload_length",
    "flow_duration", "total_pkts", "total_bytes",
    "packet_rate", "byte_rate", "avg_packet_size",
}


# ============================================================
# OUTPUT BUFFER
# ============================================================

REPORT_LINES = []


def log(text=""):
    print(text)
    REPORT_LINES.append(str(text))


# ============================================================
# F-SCORE
# ============================================================

def f_scores(df, features):
    out = []
    for col in features:
        groups = []
        for lbl in LABELS:
            vals = df.loc[df["label"] == lbl, col].dropna()
            if len(vals) > 0:
                groups.append(vals)
        if len(groups) < 2:
            continue
        all_vals = pd.concat(groups, ignore_index=True)
        gm = all_vals.mean()
        b = sum(len(g) * (g.mean() - gm) ** 2 for g in groups)
        w = sum(
            (len(g) - 1) * g.var()
            for g in groups if not np.isnan(g.var())
        )
        out.append((col, b / w if w > 0 else np.inf))
    out.sort(key=lambda x: -x[1] if np.isfinite(x[1]) else -1e30)
    return out


# ============================================================
# GROUP BUILDER
# ============================================================

def build_groups(df):
    if "run_id" not in df.columns:
        return None
    rid = df["run_id"].fillna("").astype(str).str.strip()
    groups = pd.Series(index=df.index, dtype="object")

    attack = (df["label"] != "normal") & (rid != "")
    groups.loc[attack] = "attack_" + rid.loc[attack]

    normal_mask = (df["label"] == "normal") | (rid == "")
    idx = df.index[normal_mask].tolist()
    for i in range(0, len(idx), NORMAL_GROUP_SIZE):
        chunk = idx[i:i + NORMAL_GROUP_SIZE]
        groups.loc[chunk] = f"normal_group_{i // NORMAL_GROUP_SIZE:04d}"
    return groups.astype(str)


# ============================================================
# RF IMPORTANCE
# ============================================================

def rf_importance(df, features):
    X = df[features].replace([np.inf, -np.inf], np.nan).fillna(0)
    y = df["label"].astype(str)
    enc = LabelEncoder()
    y_e = enc.fit_transform(y)
    groups = build_groups(df)

    if groups is not None and groups.nunique() > 1:
        splitter = GroupShuffleSplit(
            n_splits=1, test_size=TEST_SIZE, random_state=RANDOM_STATE
        )
        try:
            tr, te = next(splitter.split(X, y_e, groups=groups))
        except Exception:
            tr, te = _fallback_split(X, y_e)
    else:
        tr, te = _fallback_split(X, y_e)

    model = RandomForestClassifier(
        n_estimators=RF_TREES,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",
    )
    start = time.time()
    model.fit(X.iloc[tr], y_e[tr])
    return list(zip(features, model.feature_importances_))


def _fallback_split(X, y):
    from sklearn.model_selection import train_test_split
    idx = np.arange(len(X))
    return train_test_split(
        idx, test_size=TEST_SIZE,
        random_state=RANDOM_STATE, stratify=y
    )


# ============================================================
# REDUNDANCY
# ============================================================

def redundancy(df, features):
    if len(features) < 2:
        return []
    corr = df[features].corr().abs()
    upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
    pairs = []
    for col in upper.columns:
        for row in upper.index:
            v = upper.loc[row, col]
            if pd.notna(v) and v >= CORR_THRESHOLD:
                pairs.append((row, col, v))
    pairs.sort(key=lambda x: -x[2])
    return pairs


# ============================================================
# DECISION LOGIC
# ============================================================

def decide(feature, rf, f, online):
    if feature in IDENTIFIER_COLS:
        return "DROP", "Identifier — not a behaviour feature"

    if feature in NON_FEATURE_COLS:
        return "DROP", "Non-feature (grouping / target)"

    if not online:
        return "DROP", "Not available in TrafficMonitor (serving mismatch)"

    if rf >= 0.05:
        return "KEEP", f"Strong RF importance ({rf:.4f})"

    if rf >= 0.005 or (np.isfinite(f) and f >= 0.1):
        return "KEEP", f"Moderate signal (RF={rf:.4f}, F={f:.4f})"

    if rf > 0 and np.isfinite(f) and f > 0.001:
        return "REVIEW", "Weak but non-zero signal"

    if rf == 0 and (np.isinf(f) or f < 0.001):
        return "DROP", "No signal (constant / zero)"

    return "REVIEW", "Unclear — review manually"


# ============================================================
# ANALYSIS
# ============================================================

def analyze(name, path):
    log()
    log("=" * 80)
    log(f"  {name}")
    log("=" * 80)
    log(f"File: {path}")

    if not path.exists():
        log(f"[ERROR] File not found: {path}")
        return None

    df = pd.read_csv(path, low_memory=False)

    log(f"Rows    : {len(df):,}")
    log(f"Columns : {len(df.columns)}")

    # ---------------- Column inventory ----------------
    log()
    log("-" * 80)
    log("COLUMN INVENTORY")
    log("-" * 80)

    feature_cols = []
    for i, col in enumerate(df.columns, 1):
        unique = df[col].nunique(dropna=True)
        nan = int(df[col].isna().sum())

        if col == "label":
            role = "TARGET"
        elif col in NON_FEATURE_COLS:
            role = "GROUPING/ID"
        elif col in IDENTIFIER_COLS:
            role = "IDENTIFIER"
        elif pd.api.types.is_numeric_dtype(df[col]):
            role = "FEATURE"
            feature_cols.append(col)
        else:
            role = "OTHER"

        log(
            f"{i:<4}{col:<24}{str(df[col].dtype):<12}"
            f"{unique:>10,}{nan:>10,}  {role}"
        )

    # ---------------- F-score ----------------
    log()
    log("-" * 80)
    log("F-SCORE")
    log("-" * 80)

    fs = f_scores(df, feature_cols)
    f_map = dict(fs)

    for rank, (feat, score) in enumerate(fs, 1):
        s = "inf" if np.isinf(score) else f"{score:.6f}"
        log(f"{rank:<4}{feat:<28}{s:>14}")

    # ---------------- Redundancy ----------------
    log()
    log("-" * 80)
    log(f"REDUNDANCY (|r| >= {CORR_THRESHOLD})")
    log("-" * 80)

    red = redundancy(df, feature_cols)
    if not red:
        log("[PASS] No redundant pairs.")
    else:
        for a, b, r in red:
            log(f"{a:<28} ↔ {b:<28} |r|={r:.4f}")

    # ---------------- RF importance ----------------
    log()
    log("-" * 80)
    log("RANDOM FOREST IMPORTANCE")
    log("-" * 80)

    rf_list = rf_importance(df, feature_cols)
    rf_map = dict(rf_list)

    for rank, (feat, imp) in enumerate(rf_list, 1):
        log(f"{rank:<4}{feat:<28}{imp:>14.8f}")

    # ---------------- Decision table ----------------
    log()
    log("-" * 80)
    log("FEATURE SELECTION DECISION")
    log("-" * 80)

    log(
        f"{'Feature':<28}"
        f"{'RF':>10}"
        f"{'F-score':>12}"
        f"{'Online':>8}"
        f"  Decision"
    )
    log("-" * 80)

    decisions = []
    for feat in feature_cols:
        rf = rf_map.get(feat, 0.0)
        f = f_map.get(feat, 0.0)
        online = feat in ONLINE_AVAILABLE

        decision, reason = decide(feat, rf, f, online)
        decisions.append({
            "feature": feat,
            "rf": rf,
            "f_score": f,
            "online": online,
            "decision": decision,
            "reason": reason,
        })

        f_str = "inf" if np.isinf(f) else f"{f:.4f}"
        online_str = "yes" if online else "NO"
        log(
            f"{feat:<28}"
            f"{rf:>10.5f}"
            f"{f_str:>12}"
            f"{online_str:>8}"
            f"  {decision}"
        )

    # ---------------- Final lists ----------------
    log()
    log("-" * 80)
    log("FINAL LISTS")
    log("-" * 80)

    for decision in ["KEEP", "REVIEW", "DROP"]:
        feats = [d["feature"] for d in decisions if d["decision"] == decision]
        log()
        log(f"{decision} ({len(feats)}):")
        for f in feats:
            log(f"  - {f}")

    # ---------------- SYN Flood candidates ----------------
    log()
    log("-" * 80)
    log("SYN FLOOD FEATURE CANDIDATES (proposed, not added)")
    log("-" * 80)

    syn_candidates = []

    if name.startswith("PACKET"):
        syn_candidates = [
            ("syn_ack_ratio", "syn / (ack + 1) — SYN dominance"),
            ("is_syn_only", "(syn=1) AND (ack=0)"),
            ("is_syn_ack", "(syn=1) AND (ack=1)"),
            ("pkt_size_class", "bin(packet_length)"),
        ]
    elif name.startswith("FLOW"):
        syn_candidates = [
            ("syn_pkt_ratio", "SYN packets / total_pkts"),
            ("pkt_density", "total_pkts / (flow_duration + 1)"),
            ("bytes_per_pkt", "total_bytes / (total_pkts + 1)"),
            ("flow_intensity", "packet_rate / (flow_duration + 1)"),
        ]

    for fname, desc in syn_candidates:
        log(f"  + {fname:<22} → {desc}")

    # ---------------- Return ----------------
    return {
        "df": df,
        "features": feature_cols,
        "decisions": decisions,
        "redundancy": red,
        "syn_candidates": syn_candidates,
    }


# ============================================================
# MAIN
# ============================================================

log("#" * 80)
log("#  FEATURE SELECTION REPORT — READ ONLY".center(78) + "#")
log("#" * 80)

packet_res = analyze("PACKET ML", PACKET_FILE)
flow_res = analyze("FLOW ML", FLOW_FILE)


# ============================================================
# COMPARISON
# ============================================================

if packet_res and flow_res:
    log()
    log("=" * 80)
    log("  PACKET vs FLOW")
    log("=" * 80)

    p_cols = set(packet_res["df"].columns)
    f_cols = set(flow_res["df"].columns)

    common = p_cols & f_cols
    p_only = p_cols - f_cols
    f_only = f_cols - p_cols

    log(f"Common : {len(common)}")
    log(f"Packet-only : {len(p_only)}")
    log(f"Flow-only   : {len(f_only)}")

    log()
    log("Packet-only:")
    for c in sorted(p_only):
        log(f"  - {c}")

    log()
    log("Flow-only:")
    for c in sorted(f_only):
        log(f"  - {c}")


# ============================================================
# SAVE REPORT
# ============================================================

try:
    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(REPORT_LINES))
    log()
    log(f"[REPORT SAVED] {REPORT_MD}")
except Exception as e:
    log(f"[WARNING] Could not save MD: {e}")


# Save summary CSV
try:
    rows = []
    if packet_res:
        for d in packet_res["decisions"]:
            rows.append({"dataset": "packet", **d})
    if flow_res:
        for d in flow_res["decisions"]:
            rows.append({"dataset": "flow", **d})

    pd.DataFrame(rows).to_csv(REPORT_CSV, index=False)
    log(f"[CSV SAVED] {REPORT_CSV}")
except Exception as e:
    log(f"[WARNING] Could not save CSV: {e}")


log()
log("=" * 80)
log("DONE — READ-ONLY")
log("=" * 80)

