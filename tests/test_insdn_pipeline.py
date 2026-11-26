"""Unit tests for InSDN leakage stripping, deduplication, and observability-tier loading."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from data.insdn_loader import (
    LEAKAGE_IDENTIFIER_COLS,
    TIER_1A_UNIDIRECTIONAL_OF,
    audit_insdn_dataframe,
    load_clean_insdn,
)


def _make_sample_insdn_csv(tmp_path: Path) -> Path:
    rows = [
        {
            "Flow ID": "f1",
            "Src IP": "10.0.0.1",
            "Src Port": 50000,
            "Dst IP": "10.0.0.3",
            "Dst Port": 80,
            "Protocol": 6,
            "Timestamp": "5/2/2020 13:58",
            "Flow Duration": 1000,
            "Tot Fwd Pkts": 10,
            "Tot Bwd Pkts": 8,
            "TotLen Fwd Pkts": 500,
            "TotLen Bwd Pkts": 400,
            "Flow Byts/s": 900.0,
            "Flow Pkts/s": 18.0,
            "Fwd Pkts/s": 10.0,
            "Bwd Pkts/s": 8.0,
            "Fwd Pkt Len Mean": 50.0,
            "Pkt Size Avg": 50.0,
            "Down/Up Ratio": 0.8,
            "ConstCol": 0,
            "Label": "Normal",
        },
        # Exact duplicate feature vector with different Flow ID (must be deduplicated)
        {
            "Flow ID": "f2",
            "Src IP": "10.0.0.1",
            "Src Port": 50001,
            "Dst IP": "10.0.0.3",
            "Dst Port": 80,
            "Protocol": 6,
            "Timestamp": "5/2/2020 13:59",
            "Flow Duration": 1000,
            "Tot Fwd Pkts": 10,
            "Tot Bwd Pkts": 8,
            "TotLen Fwd Pkts": 500,
            "TotLen Bwd Pkts": 400,
            "Flow Byts/s": 900.0,
            "Flow Pkts/s": 18.0,
            "Fwd Pkts/s": 10.0,
            "Bwd Pkts/s": 8.0,
            "Fwd Pkt Len Mean": 50.0,
            "Pkt Size Avg": 50.0,
            "Down/Up Ratio": 0.8,
            "ConstCol": 0,
            "Label": "Normal",
        },
        {
            "Flow ID": "f3",
            "Src IP": "10.0.0.99",
            "Src Port": 12345,
            "Dst IP": "10.0.0.3",
            "Dst Port": 9999,
            "Protocol": 17,
            "Timestamp": "5/2/2020 14:00",
            "Flow Duration": 200,
            "Tot Fwd Pkts": 500,
            "Tot Bwd Pkts": 0,
            "TotLen Fwd Pkts": 32000,
            "TotLen Bwd Pkts": 0,
            "Flow Byts/s": 160000.0,
            "Flow Pkts/s": 2500.0,
            "Fwd Pkts/s": 2500.0,
            "Bwd Pkts/s": 0.0,
            "Fwd Pkt Len Mean": 64.0,
            "Pkt Size Avg": 64.0,
            "Down/Up Ratio": 0.0,
            "ConstCol": 0,
            "Label": "DDoS",
        },
    ]
    p = tmp_path / "sample_insdn.csv"
    pd.DataFrame(rows).to_csv(p, index=False)
    return p


def test_insdn_loader_strips_leakage_and_deduplicates(tmp_path: Path) -> None:
    csv_path = _make_sample_insdn_csv(tmp_path)
    df = pd.read_csv(csv_path)
    audit = audit_insdn_dataframe(df)
    assert audit["feature_only_duplicates_no_id"] == 1
    assert "ConstCol" in audit["zero_variance_columns"]

    X, y_bin, y_mc, tiers = load_clean_insdn(csv_path, include_dst_port=False, deduplicate_features=True)
    assert len(X) == 2
    for leak in LEAKAGE_IDENTIFIER_COLS + ["Dst Port", "ConstCol"]:
        assert leak not in X.columns
    assert set(TIER_1A_UNIDIRECTIONAL_OF).issubset(set(tiers["T1a_Unidirectional_OF"]))
    assert y_bin.tolist() == [0, 1]
    assert y_mc.tolist() == ["Normal", "DDoS"]
