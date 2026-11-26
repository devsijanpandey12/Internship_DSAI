"""Download raw InSDN dataset, compute SHA-256 manifest, and print leakage audit."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from data.insdn_loader import (  # noqa: E402
    INSDN_HF_URL,
    audit_insdn_dataframe,
    download_insdn,
    save_insdn_manifest,
)


def main() -> None:
    raw_path = REPO_ROOT / "data" / "raw" / "insdn" / "Dataset.csv"
    manifest_path = REPO_ROOT / "data" / "manifests" / "insdn_manifest.json"

    print(f"Downloading InSDN from {INSDN_HF_URL} -> {raw_path} ...", flush=True)
    download_insdn(raw_path)
    print(f"Download complete: {raw_path.stat().st_size / (1024 * 1024):.2f} MB", flush=True)

    print("Running full schema, duplicate, and leakage audit ...", flush=True)
    df = pd.read_csv(raw_path, low_memory=False)
    audit = audit_insdn_dataframe(df)
    save_insdn_manifest(raw_path, manifest_path, audit)

    print("\n=== INSDN AUDIT SUMMARY ===")
    summary_keys = [
        "n_rows",
        "n_columns",
        "binary_distribution",
        "label_distribution",
        "exact_row_duplicates",
        "feature_only_duplicates_no_id",
        "nan_cells_in_features",
        "inf_cells_in_features",
        "zero_variance_columns",
        "ip_shortcut_leakage_audit",
        "dst_port_audit",
        "observability_tiers",
    ]
    print(json.dumps({k: audit[k] for k in summary_keys}, indent=2))
    print(f"\nSaved manifest -> {manifest_path}")


if __name__ == "__main__":
    main()
