"""
feature_leakage_analysis.py
---------------------------
Read-only Feature Selection & Leakage Analysis

Analyzes:
    1. Column inventory
    2. Label distribution
    3. Per-label means
    4. ANOVA-style F-score
    5. Correlation / redundancy
    6. Random Forest feature importance
       (group-aware split to avoid leakage)
    7. Classification report (analysis only)
    8. Leakage / identifier review
    9. Initial recommendation
    10. Packet vs Flow comparison

IMPORTANT:
    - Does NOT modify ML_FINAL datasets.
    - Does NOT delete features.
    - Does NOT train the final AI model.
    - Random Forest here is ONLY for feature-importance
      analysis, NOT the final model.
"""

import os
import time
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import classification_report


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(
    os.environ.get(
        "IOT_BASE_DIR",
        Path.home() / "IoT-devices"
    )
)

PACKET_FILE = (
    BASE_DIR
    / "ML_FINAL"
    / "labeled_packet_features_ML.csv"
)

FLOW_FILE = (
    BASE_DIR
    / "ML_FINAL"
    / "labeled_traffic_features_ML.csv"
)

REPORT_FILE = (
    BASE_DIR
    / "feature_leakage_report.txt"
)


# ============================================================
# CONFIG
# ============================================================

NON_FEATURE_COLS = {
    "timestamp",
    "run_id",
    "label",
}

IDENTIFIER_COLS = {
    "src_mac",
    "dst_mac",
    "src_ip",
    "dst_ip",
    "switch",
}

LABELS = [
    "normal",
    "syn_flood",
    "port_scan",
    "malicious_post",
]

RANDOM_STATE = 42

RF_TREES = 100

CORRELATION_THRESHOLD = 0.90

TEST_SIZE = 0.20

# Analysis-only grouping size for normal traffic.
#
# Normal rows have empty run_id in the frozen datasets.
# We therefore create artificial groups ONLY for splitting.
# The original CSV is never modified.
NORMAL_GROUP_SIZE = 5000


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

def calculate_f_scores(df, feature_cols):

    scores = []

    labels_present = [
        lbl for lbl in LABELS
        if lbl in df["label"].values
    ]

    for col in feature_cols:

        groups = []

        for lbl in labels_present:

            values = (
                df.loc[df["label"] == lbl, col]
                .dropna()
            )

            if len(values) > 0:
                groups.append(values)

        if len(groups) < 2:
            continue

        all_values = pd.concat(
            groups,
            ignore_index=True
        )

        overall_mean = all_values.mean()

        between = 0.0
        within = 0.0

        for values in groups:

            n = len(values)
            mean = values.mean()
            variance = values.var()

            between += (
                n *
                (mean - overall_mean) ** 2
            )

            if not np.isnan(variance):
                within += (
                    (n - 1) *
                    variance
                )

        if within > 0:
            f_score = between / within
        else:
            f_score = np.inf

        scores.append(
            (col, f_score)
        )

    scores.sort(
        key=lambda x:
            -x[1]
            if np.isfinite(x[1])
            else -1e30
    )

    return scores


# ============================================================
# RANDOM SPLIT FALLBACK
# ============================================================

def _random_split(X, y):

    from sklearn.model_selection import train_test_split

    idx = np.arange(len(X))

    train_idx, test_idx = train_test_split(
        idx,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    return train_idx, test_idx


# ============================================================
# BUILD ANALYSIS-ONLY GROUPS
# ============================================================

def build_analysis_groups(df):

    """
    Build groups ONLY for train/test splitting.

    Attack rows:
        use their real run_id.

    Normal rows:
        run_id is empty in the frozen dataset.
        Split normal rows into fixed-size artificial groups.

    IMPORTANT:
        This function does NOT modify df.
        It does NOT modify run_id in the dataset.
    """

    if "run_id" not in df.columns:
        return None

    real_run_id = (
        df["run_id"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    groups = pd.Series(
        index=df.index,
        dtype="object"
    )

    # --------------------------------------------------------
    # Attack rows → real run_id
    # --------------------------------------------------------

    attack_mask = (
        (df["label"] != "normal") &
        (real_run_id != "")
    )

    groups.loc[attack_mask] = (
        "attack_" +
        real_run_id.loc[attack_mask]
    )

    # --------------------------------------------------------
    # Normal rows → artificial groups
    # --------------------------------------------------------

    normal_mask = (
        (df["label"] == "normal") |
        (real_run_id == "")
    )

    normal_indices = (
        df.index[normal_mask]
        .tolist()
    )

    for i in range(
        0,
        len(normal_indices),
        NORMAL_GROUP_SIZE
    ):

        chunk = normal_indices[
            i:i + NORMAL_GROUP_SIZE
        ]

        group_number = (
            i // NORMAL_GROUP_SIZE
        )

        groups.loc[chunk] = (
            f"normal_group_{group_number:04d}"
        )

    groups = groups.astype(str)

    return groups


# ============================================================
# RANDOM FOREST IMPORTANCE
# ============================================================

def calculate_rf_importance(
    df,
    feature_cols
):

    X = df[feature_cols].copy()

    y = df["label"].astype(str)

    # --------------------------------------------------------
    # Replace invalid numeric values
    # --------------------------------------------------------

    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    X = X.fillna(0)

    # --------------------------------------------------------
    # Encode labels
    # --------------------------------------------------------

    encoder = LabelEncoder()

    y_encoded = encoder.fit_transform(y)

    # --------------------------------------------------------
    # Build analysis-only groups
    # --------------------------------------------------------

    groups = build_analysis_groups(df)

    if groups is not None:

        log()
        log(
            "[INFO] Analysis-only grouping enabled"
        )

        log(
            "       Attack rows → real run_id"
        )

        log(
            "       Normal rows → groups of "
            f"{NORMAL_GROUP_SIZE:,} rows"
        )

        log(
            "       Total groups: "
            f"{groups.nunique()}"
        )

    # --------------------------------------------------------
    # Group-aware split
    # --------------------------------------------------------

    if (
        groups is not None and
        groups.nunique() > 1
    ):

        splitter = GroupShuffleSplit(
            n_splits=1,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
        )

        try:

            train_idx, test_idx = next(
                splitter.split(
                    X,
                    y_encoded,
                    groups=groups
                )
            )

            log()
            log(
                "[INFO] Group-aware split "
                "completed successfully"
            )

            log(
                f"       Groups used: "
                f"{groups.nunique()}"
            )

        except Exception as e:

            log(
                f"[WARNING] Group split failed: {e}"
            )

            log(
                "[INFO] Falling back to random "
                "split (analysis only)"
            )

            train_idx, test_idx = (
                _random_split(
                    X,
                    y_encoded
                )
            )

    else:

        log()
        log(
            "[INFO] Not enough groups "
            "→ using random split "
            "(analysis only)"
        )

        train_idx, test_idx = (
            _random_split(
                X,
                y_encoded
            )
        )

    # --------------------------------------------------------
    # Train / Test data
    # --------------------------------------------------------

    X_train = X.iloc[train_idx]

    X_test = X.iloc[test_idx]

    y_train = y_encoded[train_idx]

    y_test = y_encoded[test_idx]

    log()
    log(
        f"[INFO] Training rows: "
        f"{len(X_train):,}"
    )

    log(
        f"[INFO] Testing rows : "
        f"{len(X_test):,}"
    )

    # --------------------------------------------------------
    # Random Forest
    # --------------------------------------------------------

    model = RandomForestClassifier(
        n_estimators=RF_TREES,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",
        max_depth=None,
    )

    start = time.time()

    model.fit(
        X_train,
        y_train
    )

    train_time = (
        time.time() - start
    )

    log()
    log(
        f"[INFO] RF trained in "
        f"{train_time:.2f} seconds"
    )

    # --------------------------------------------------------
    # Feature importance
    # --------------------------------------------------------

    importance = list(
        zip(
            feature_cols,
            model.feature_importances_
        )
    )

    importance.sort(
        key=lambda x: x[1],
        reverse=True
    )

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

    y_pred = model.predict(
        X_test
    )

    report = classification_report(
        y_test,
        y_pred,
        target_names=encoder.classes_,
        digits=4,
        zero_division=0,
    )

    return {
        "importance": importance,
        "classification_report": report,
        "train_time": train_time,
    }


# ============================================================
# CORRELATION / REDUNDANCY
# ============================================================

def calculate_redundancy(
    df,
    feature_cols
):

    if len(feature_cols) < 2:
        return []

    corr = (
        df[feature_cols]
        .corr()
        .abs()
    )

    upper = corr.where(
        np.triu(
            np.ones(corr.shape),
            k=1
        ).astype(bool)
    )

    high_corr = []

    for col in upper.columns:

        for row in upper.index:

            value = upper.loc[
                row,
                col
            ]

            if (
                pd.notna(value) and
                value >= CORRELATION_THRESHOLD
            ):

                high_corr.append(
                    (
                        row,
                        col,
                        value
                    )
                )

    high_corr.sort(
        key=lambda x: -x[2]
    )

    return high_corr


# ============================================================
# DATASET ANALYSIS
# ============================================================

def analyze_dataset(
    name,
    path
):

    log()
    log("=" * 80)
    log(f"  {name}")
    log("=" * 80)

    log(
        f"File: {path}"
    )

    if not path.exists():

        log(
            f"[ERROR] File not found: {path}"
        )

        return None

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    df = pd.read_csv(
        path,
        low_memory=False
    )

    log()
    log(
        f"Rows    : {len(df):,}"
    )

    log(
        f"Columns : {len(df.columns)}"
    )

    # ========================================================
    # 1. COLUMN INVENTORY
    # ========================================================

    log()
    log("-" * 80)
    log("1. COLUMN INVENTORY")
    log("-" * 80)

    log(
        f"{'#':<4}"
        f"{'Column':<24}"
        f"{'Dtype':<12}"
        f"{'Unique':>10}"
        f"{'NaN':>10}"
        f"  Role"
    )

    log("-" * 80)

    feature_cols = []

    for i, col in enumerate(
        df.columns,
        1
    ):

        unique = df[col].nunique(
            dropna=True
        )

        nan_count = int(
            df[col].isna().sum()
        )

        if col == "label":

            role = "TARGET"

        elif col in NON_FEATURE_COLS:

            role = "GROUPING/ID"

        elif col in IDENTIFIER_COLS:

            role = "IDENTIFIER / REVIEW"

        elif pd.api.types.is_numeric_dtype(
            df[col]
        ):

            role = "FEATURE"

            feature_cols.append(col)

        else:

            role = "OTHER"

        log(
            f"{i:<4}"
            f"{col:<24}"
            f"{str(df[col].dtype):<12}"
            f"{unique:>10,}"
            f"{nan_count:>10,}"
            f"  {role}"
        )

    # ========================================================
    # 2. LABEL DISTRIBUTION
    # ========================================================

    log()
    log("-" * 80)
    log("2. LABEL DISTRIBUTION")
    log("-" * 80)

    counts = (
        df["label"]
        .value_counts()
    )

    total = len(df)

    for label, count in counts.items():

        pct = (
            count /
            total *
            100
        )

        log(
            f"{label:<20}"
            f"{count:>10,} "
            f"({pct:6.2f}%)"
        )

    # ========================================================
    # 3. PER-LABEL MEANS
    # ========================================================

    log()
    log("-" * 80)
    log("3. PER-LABEL MEANS")
    log("-" * 80)

    log(
        f"{'Feature':<24}"
        f"{'normal':>15}"
        f"{'syn_flood':>15}"
        f"{'port_scan':>15}"
        f"{'malicious_post':>18}"
    )

    log("-" * 90)

    for col in feature_cols:

        values = []

        for label in LABELS:

            subset = df.loc[
                df["label"] == label,
                col
            ]

            if len(subset) > 0:

                values.append(
                    f"{subset.mean():.4f}"
                )

            else:

                values.append(
                    "N/A"
                )

        log(
            f"{col:<24}"
            f"{values[0]:>15}"
            f"{values[1]:>15}"
            f"{values[2]:>15}"
            f"{values[3]:>18}"
        )

    # ========================================================
    # 4. F-SCORE
    # ========================================================

    log()
    log("-" * 80)
    log(
        "4. LABEL ASSOCIATION — F-SCORE"
    )
    log("-" * 80)

    f_scores = calculate_f_scores(
        df,
        feature_cols
    )

    log(
        f"{'Rank':<6}"
        f"{'Feature':<30}"
        f"{'F-Score':>18}"
    )

    log("-" * 58)

    for rank, (
        feature,
        score
    ) in enumerate(
        f_scores,
        1
    ):

        if np.isinf(score):

            score_text = "inf"

        else:

            score_text = (
                f"{score:.6f}"
            )

        log(
            f"{rank:<6}"
            f"{feature:<30}"
            f"{score_text:>18}"
        )

    # ========================================================
    # 5. REDUNDANCY
    # ========================================================

    log()
    log("-" * 80)

    log(
        "5. REDUNDANCY — "
        f"|CORRELATION| >= "
        f"{CORRELATION_THRESHOLD}"
    )

    log("-" * 80)

    redundancy = calculate_redundancy(
        df,
        feature_cols
    )

    if not redundancy:

        log(
            "[PASS] No highly correlated "
            "feature pairs."
        )

    else:

        log(
            f"{'Feature A':<30}"
            f"{'Feature B':<30}"
            f"{'|r|':>10}"
        )

        log("-" * 72)

        for a, b, r in redundancy:

            log(
                f"{a:<30}"
                f"{b:<30}"
                f"{r:>10.4f}"
            )

    # ========================================================
    # 6. RANDOM FOREST IMPORTANCE
    # ========================================================

    log()
    log("-" * 80)

    log(
        "6. RANDOM FOREST FEATURE IMPORTANCE"
    )

    log("-" * 80)

    rf_result = calculate_rf_importance(
        df,
        feature_cols
    )

    rf_importance = (
        rf_result["importance"]
    )

    classification_rep = (
        rf_result["classification_report"]
    )

    log()
    log(
        f"{'Rank':<6}"
        f"{'Feature':<30}"
        f"{'Importance':>18}"
    )

    log("-" * 58)

    for rank, (
        feature,
        importance
    ) in enumerate(
        rf_importance,
        1
    ):

        log(
            f"{rank:<6}"
            f"{feature:<30}"
            f"{importance:>18.8f}"
        )

    # ========================================================
    # 6b. CLASSIFICATION REPORT
    # ========================================================

    log()
    log("-" * 80)

    log(
        "6b. CLASSIFICATION REPORT "
        "(analysis only)"
    )

    log("-" * 80)

    log(
        classification_rep
    )

    # ========================================================
    # 7. LEAKAGE / IDENTIFIER REVIEW
    # ========================================================

    log()
    log("-" * 80)

    log(
        "7. LEAKAGE / IDENTIFIER REVIEW"
    )

    log("-" * 80)

    for col in sorted(
        NON_FEATURE_COLS
    ):

        if col in df.columns:

            log(
                f"[DROP FROM MODEL] {col}"
            )

    for col in sorted(
        IDENTIFIER_COLS
    ):

        if col in df.columns:

            log(
                f"[REVIEW / LIKELY DROP] {col}"
            )

    # ========================================================
    # 8. INITIAL RECOMMENDATION
    # ========================================================

    log()
    log("-" * 80)

    log(
        "8. INITIAL RECOMMENDATION"
    )

    log("-" * 80)

    importance_map = dict(
        rf_importance
    )

    f_map = dict(
        f_scores
    )

    for feature in feature_cols:

        f = f_map.get(
            feature,
            0
        )

        imp = importance_map.get(
            feature,
            0
        )

        if feature in IDENTIFIER_COLS:

            recommendation = (
                "DROP / REVIEW"
            )

        elif (
            imp >= 0.01 and
            (
                np.isinf(f) or
                f > 10
            )
        ):

            recommendation = "KEEP"

        elif (
            imp >= 0.001 or
            (
                np.isfinite(f) and
                f > 1
            )
        ):

            recommendation = "REVIEW"

        else:

            recommendation = "REVIEW"

        log(
            f"{feature:<30}"
            f"F={f:>12.4f}  "
            f"RF={imp:>10.6f}  "
            f"→ {recommendation}"
        )

    # ========================================================
    # RETURN
    # ========================================================

    return {
        "df": df,
        "features": feature_cols,
        "f_scores": f_scores,
        "rf_importance": rf_importance,
        "redundancy": redundancy,
    }


# ============================================================
# MAIN
# ============================================================

log()

log(
    "#" * 80
)

log(
    "#" +
    "  FEATURE SELECTION & LEAKAGE ANALYSIS".center(78) +
    "#"
)

log(
    "#" * 80
)

packet_result = analyze_dataset(
    "PACKET ML",
    PACKET_FILE
)

flow_result = analyze_dataset(
    "FLOW ML",
    FLOW_FILE
)


# ============================================================
# PACKET vs FLOW
# ============================================================

if (
    packet_result is not None and
    flow_result is not None
):

    packet_df = (
        packet_result["df"]
    )

    flow_df = (
        flow_result["df"]
    )

    log()
    log("=" * 80)

    log(
        "  PACKET vs FLOW FEATURE COMPARISON"
    )

    log("=" * 80)

    packet_cols = set(
        packet_df.columns
    )

    flow_cols = set(
        flow_df.columns
    )

    common = (
        packet_cols &
        flow_cols
    )

    packet_only = (
        packet_cols -
        flow_cols
    )

    flow_only = (
        flow_cols -
        packet_cols
    )

    log()

    log(
        f"Common features : "
        f"{len(common)}"
    )

    log(
        f"Packet-only     : "
        f"{len(packet_only)}"
    )

    log(
        f"Flow-only       : "
        f"{len(flow_only)}"
    )

    log()
    log("Packet-only:")

    for col in sorted(
        packet_only
    ):

        log(
            f"  - {col}"
        )

    log()
    log("Flow-only:")

    for col in sorted(
        flow_only
    ):

        log(
            f"  - {col}"
        )


# ============================================================
# SAVE REPORT
# ============================================================

try:

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(
                REPORT_LINES
            )
        )

    log()
    log(
        f"[REPORT SAVED] "
        f"{REPORT_FILE}"
    )

except Exception as e:

    log()
    log(
        f"[WARNING] "
        f"Could not save report: {e}"
    )


# ============================================================
# END
# ============================================================

log()

log("=" * 80)

log(
    "DONE — READ-ONLY ANALYSIS"
)

log("=" * 80)
