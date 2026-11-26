"""InSDN dataset acquisition, manifest hashing, leakage auditing, and observability-tier mapping."""

from __future__ import annotations

import datetime as dt
import json
import urllib.request
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from evaluation.metrics import sha256_file

INSDN_HF_URL = "https://huggingface.co/datasets/Sharukesh/INSDN/resolve/main/Dataset.csv"

# Strict identifier / leakage columns that MUST be excluded from model features
LEAKAGE_IDENTIFIER_COLS = [
    "Flow ID",
    "Src IP",
    "Dst IP",
    "Timestamp",
    "Src Port",
]

# Feature observability tiers grounded in OpenFlow 1.3 control-plane mechanics:
# - T1a: Strictly unidirectional OpenFlow flow-entry counters (zero per-packet buffering)
# - T1b: Paired bidirectional OpenFlow flow-entry counters (forward + reverse flow rules)
# - T2:  Adds TCP flags / header / window fields (requires Packet-In header inspection)
# - T3:  Full CICFlowMeter-style statistical features (requires per-packet buffering & IAT/length std)
TIER_1A_UNIDIRECTIONAL_OF = [
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "TotLen Fwd Pkts",
    "Fwd Pkts/s",
    "Fwd Pkt Len Mean",
]

TIER_1B_BIDIRECTIONAL_OF = [
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "Pkt Size Avg",
    "Down/Up Ratio",
]

TIER_2_HEADER_FLAGS = TIER_1B_BIDIRECTIONAL_OF + [
    "Fwd Header Len",
    "Bwd Header Len",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "URG Flag Cnt",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
]


def download_insdn(dest_path: Path, url: str = INSDN_HF_URL, force: bool = False) -> Path:
    """Download raw InSDN Dataset.csv to data/raw/insdn/ without overwriting unless forced."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    if dest_path.exists() and not force:
        return dest_path
    tmp_path = dest_path.with_suffix(".csv.part")
    req = urllib.request.Request(url, headers={"User-Agent": "KU-DSAI-Research-Downloader/0.1"})
    with urllib.request.urlopen(req, timeout=120) as resp, tmp_path.open("wb") as out:
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
    tmp_path.replace(dest_path)
    return dest_path


def _resolve_label_series(df: pd.DataFrame) -> tuple[str, pd.Series, pd.Series]:
    """Resolve either string 'Label' or binary integer 'target' (0=Normal, 1=Attack)."""
    if "Label" in df.columns:
        label_col = "Label"
        mc = df[label_col].astype(str).str.strip()
        binary = (mc.str.lower() != "normal").astype(int)
        return label_col, binary, mc
    if "target" in df.columns:
        label_col = "target"
        raw = df[label_col]
        if pd.api.types.is_numeric_dtype(raw):
            binary = (raw.astype(int) != 0).astype(int)
            mc = binary.map({0: "Normal", 1: "Attack"})
        else:
            mc = raw.astype(str).str.strip()
            binary = (mc.str.lower() != "normal").astype(int)
        return label_col, binary, mc
    raise ValueError(f"Expected 'Label' or 'target' column in InSDN; got {df.columns[-5:].tolist()}")


def audit_insdn_dataframe(df: pd.DataFrame) -> dict[str, Any]:
    """Perform a leakage, duplicate, missing/Inf, and schema audit on raw InSDN."""
    df_cols = [c.strip() for c in df.columns]
    df = df.copy()
    df.columns = df_cols

    label_col, labels_binary, labels_clean = _resolve_label_series(df)
    label_counts = labels_clean.value_counts().to_dict()

    # Exact row duplicates vs. feature-only duplicates (after removing identifiers)
    n_rows = int(len(df))
    exact_dups = int(df.duplicated().sum())

    present_leak_cols = [c for c in LEAKAGE_IDENTIFIER_COLS if c in df.columns]
    feature_cols_no_id = [c for c in df.columns if c not in present_leak_cols and c != label_col]
    feature_dups = int(df.duplicated(subset=feature_cols_no_id).sum())

    numeric_df = df[feature_cols_no_id].apply(pd.to_numeric, errors="coerce")
    nan_cells = int(numeric_df.isna().sum().sum())
    inf_cells = int(np.isinf(numeric_df.to_numpy(dtype=np.float64, na_value=0.0)).sum())
    zero_var_cols = [c for c in numeric_df.columns if numeric_df[c].nunique(dropna=True) <= 1]

    # Check IP-level separation (quantifies why keeping Src/Dst IP causes shortcut learning!)
    ip_audit: dict[str, Any] = {}
    for ip_col in ("Src IP", "Dst IP"):
        if ip_col in df.columns:
            normal_ips = set(df.loc[labels_clean.str.lower() == "normal", ip_col].astype(str))
            attack_ips = set(df.loc[labels_clean.str.lower() != "normal", ip_col].astype(str))
            overlap = normal_ips & attack_ips
            ip_audit[ip_col] = {
                "unique_normal": len(normal_ips),
                "unique_attack": len(attack_ips),
                "overlap_count": len(overlap),
                "attack_rows_with_attack_only_ip_pct": round(
                    100.0
                    * float(
                        df.loc[labels_clean.str.lower() != "normal", ip_col]
                        .astype(str)
                        .isin(attack_ips - normal_ips)
                        .mean()
                    ),
                    2,
                ),
            }

    # Check Dst Port concentration across normal vs attack (potential lab-service shortcut!)
    dst_port_audit: dict[str, Any] = {}
    if "Dst Port" in df.columns:
        top_norm = df.loc[labels_clean.str.lower() == "normal", "Dst Port"].value_counts().head(5).to_dict()
        top_atk = df.loc[labels_clean.str.lower() != "normal", "Dst Port"].value_counts().head(5).to_dict()
        dst_port_audit = {
            "top5_normal_dst_ports": {str(k): int(v) for k, v in top_norm.items()},
            "top5_attack_dst_ports": {str(k): int(v) for k, v in top_atk.items()},
        }

    # Verify observability-tier column availability
    tier_check = {
        "T1a_Unidirectional_OF": [c for c in TIER_1A_UNIDIRECTIONAL_OF if c in df.columns],
        "T1a_missing": [c for c in TIER_1A_UNIDIRECTIONAL_OF if c not in df.columns],
        "T1b_Bidirectional_OF": [c for c in TIER_1B_BIDIRECTIONAL_OF if c in df.columns],
        "T1b_missing": [c for c in TIER_1B_BIDIRECTIONAL_OF if c not in df.columns],
        "T2_Header_Flags": [c for c in TIER_2_HEADER_FLAGS if c in df.columns],
        "T2_missing": [c for c in TIER_2_HEADER_FLAGS if c not in df.columns],
        "T3_clean_numeric_count": len([c for c in feature_cols_no_id if c not in zero_var_cols and c != "Dst Port"]),
    }

    return {
        "n_rows": n_rows,
        "n_columns": int(len(df.columns)),
        "columns": df_cols,
        "label_distribution": {str(k): int(v) for k, v in label_counts.items()},
        "binary_distribution": {
            "Normal": int((labels_clean.str.lower() == "normal").sum()),
            "Attack": int((labels_clean.str.lower() != "normal").sum()),
        },
        "exact_row_duplicates": exact_dups,
        "feature_only_duplicates_no_id": feature_dups,
        "nan_cells_in_features": nan_cells,
        "inf_cells_in_features": inf_cells,
        "zero_variance_columns": zero_var_cols,
        "leakage_identifier_columns_present": present_leak_cols,
        "ip_shortcut_leakage_audit": ip_audit,
        "dst_port_audit": dst_port_audit,
        "observability_tiers": tier_check,
    }


def load_clean_insdn(
    csv_path: Path,
    include_dst_port: bool = False,
    deduplicate_features: bool = True,
) -> tuple[pd.DataFrame, pd.Series, pd.Series, dict[str, list[str]]]:
    """Load InSDN, strip leakage columns, sanitize Inf/NaN, deduplicate, and return tier mappings."""
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]

    label_col, labels_binary, labels_multiclass = _resolve_label_series(df)

    drop_cols = [c for c in LEAKAGE_IDENTIFIER_COLS if c in df.columns]
    if not include_dst_port and "Dst Port" in df.columns:
        drop_cols.append("Dst Port")

    feature_cols = [c for c in df.columns if c not in drop_cols and c != label_col]
    X = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)

    # Drop constant / all-NaN columns
    valid_cols = [c for c in X.columns if X[c].nunique(dropna=True) > 1]
    X = X[valid_cols]

    # Fill rare NaNs with 0 only after checking finite values (or drop rows with NaN)
    finite_mask = ~X.isna().any(axis=1)
    X = X.loc[finite_mask].copy()
    labels_binary = labels_binary.loc[finite_mask].copy()
    labels_multiclass = labels_multiclass.loc[finite_mask].copy()

    if deduplicate_features:
        # Remove identical feature vectors before splitting to prevent train/test memorization leakage
        dedup_mask = ~X.duplicated(keep="first")
        X = X.loc[dedup_mask].reset_index(drop=True)
        labels_binary = labels_binary.loc[dedup_mask].reset_index(drop=True)
        labels_multiclass = labels_multiclass.loc[dedup_mask].reset_index(drop=True)
    else:
        X = X.reset_index(drop=True)
        labels_binary = labels_binary.reset_index(drop=True)
        labels_multiclass = labels_multiclass.reset_index(drop=True)

    t1a = [c for c in TIER_1A_UNIDIRECTIONAL_OF if c in X.columns]
    t1b = [c for c in TIER_1B_BIDIRECTIONAL_OF if c in X.columns]
    t2 = [c for c in TIER_2_HEADER_FLAGS if c in X.columns]
    if include_dst_port and "Dst Port" in X.columns:
        t1a = t1a + ["Dst Port"]
        t1b = t1b + ["Dst Port"]
        t2 = t2 + ["Dst Port"]

    tiers = {
        "T1a_Unidirectional_OF": t1a,
        "T1b_Bidirectional_OF": t1b,
        "T2_Header_Flags": t2,
        "T3_Full_CICFlowMeter": list(X.columns),
    }
    return X, labels_binary, labels_multiclass, tiers


def save_insdn_manifest(csv_path: Path, manifest_path: Path, audit: dict[str, Any], source_url: str = INSDN_HF_URL) -> None:
    """Persist immutable SHA-256 checksum and audit manifest under data/manifests/."""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "dataset_name": "InSDN",
        "source_url": source_url,
        "paper_doi": "10.1109/ACCESS.2020.3022633",
        "local_path": str(csv_path),
        "downloaded_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "size_bytes": csv_path.stat().st_size,
        "sha256": sha256_file(csv_path),
        "audit": audit,
    }
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")
