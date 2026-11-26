"""Unit tests for live SDN feature extractors (T1a lightweight & T3 CIC-style)."""

from __future__ import annotations

import numpy as np

from data.insdn_loader import TIER_1A_UNIDIRECTIONAL_OF
from features.live_extractors import LiveT1aExtractor, LiveT3CICExtractor


def test_live_t1a_extractor_shape_and_math() -> None:
    ext = LiveT1aExtractor(max_flows=100)
    key = ("10.1.0.1", "10.0.0.3", 50000, 9999, 17)
    v1 = ext.extract(key, pkt_len=100, now_ns=1_000_000_000)
    assert v1.shape == (1, len(TIER_1A_UNIDIRECTIONAL_OF))
    assert v1.dtype == np.float32
    assert v1[0, 0] == 17.0  # Protocol
    assert v1[0, 2] == 1.0   # Tot Fwd Pkts
    assert v1[0, 3] == 100.0  # TotLen Fwd Pkts

    v2 = ext.extract(key, pkt_len=200, now_ns=1_001_000_000)  # +1000 us
    assert v2[0, 1] == 1000.0
    assert v2[0, 2] == 2.0
    assert v2[0, 3] == 300.0
    assert v2[0, 5] == 150.0  # Fwd Pkt Len Mean
    assert np.all(np.isfinite(v2))


def test_live_t3_cic_extractor_bidirectional_65_features() -> None:
    cols = [
        "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
        "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd Pkt Len Mean", "Bwd Pkt Len Mean",
        "SYN Flag Cnt", "ACK Flag Cnt", "Init Bwd Win Byts", "Flow IAT Mean",
    ]
    ext = LiveT3CICExtractor(feature_names=cols, max_flows=100)
    v1 = ext.extract("10.0.0.1", "10.0.0.3", 55000, 80, 6, 74, 40, 0x02, 64240, 1_000_000_000)
    v2 = ext.extract("10.0.0.3", "10.0.0.1", 80, 55000, 6, 74, 40, 0x12, 29200, 1_002_000_000)
    assert v1.shape == (1, len(cols))
    assert v2.shape == (1, len(cols))
    assert v2[0, 1] == 2000.0   # Flow Duration = 2000 us
    assert v2[0, 2] == 1.0      # Tot Fwd Pkts
    assert v2[0, 3] == 1.0      # Tot Bwd Pkts
    assert v2[0, 8] == 2.0      # SYN Flag Cnt (SYN + SYN-ACK)
    assert v2[0, 9] == 1.0      # ACK Flag Cnt
    assert v2[0, 10] == 29200.0  # Init Bwd Win Byts
    assert np.all(np.isfinite(v2))
