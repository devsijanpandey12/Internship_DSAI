"""Unit tests for Phase 5 windowed OpenFlow features, TCP SYN frame builder, and async Stage-2 worker."""

from __future__ import annotations

import socket
import struct
import time
from pathlib import Path

import joblib
import numpy as np
import pytest
from sklearn.linear_model import LogisticRegression

from evaluation.traffic_gen import build_spoofed_tcp_syn_frame, ipv4_checksum, mac_to_bytes
from features.window_features import WINDOW_FEATURE_NAMES, PortWindowAccumulator
from mitigation.async_worker import AsyncStage2Worker


def test_port_window_accumulator_spoofed_vs_flash_crowd() -> None:
    # Spoofed UDP flood: 100 unique src_ips, UDP=100%, SYN/ACK=0%
    acc_flood = PortWindowAccumulator()
    for i in range(100):
        acc_flood.record(f"10.1.0.{i+1}", "10.0.0.3", 10000 + i, 17, 0, 106)
    vec_f, meta_f = acc_flood.finalize_and_reset(0.25)
    assert vec_f.shape == (1, len(WINDOW_FEATURE_NAMES))
    assert meta_f["dominant_proto"] == 17
    assert pytest.approx(meta_f["features"]["packet_in_rate_pps"], abs=1e-4) == 400.0
    assert pytest.approx(meta_f["features"]["unique_src_ip_ratio"], abs=1e-4) == 1.0
    assert pytest.approx(meta_f["features"]["src_ip_entropy_norm"], abs=1e-4) == 1.0
    assert pytest.approx(meta_f["features"]["udp_ratio"], abs=1e-4) == 1.0
    assert meta_f["features"]["tcp_ack_or_est_ratio"] == 0.0
    assert acc_flood.count == 0  # Reset cleanly

    # Benign TCP flash crowd: single client IP, mixed SYN & ACK/PSH
    acc_fc = PortWindowAccumulator()
    for i in range(50):
        acc_fc.record("10.0.0.1", "10.0.0.3", 40000 + i, 6, 0x02, 74)   # SYN
        acc_fc.record("10.0.0.1", "10.0.0.3", 40000 + i, 6, 0x10, 66)   # ACK
    vec_b, meta_b = acc_fc.finalize_and_reset(0.25)
    assert vec_b.shape == (1, len(WINDOW_FEATURE_NAMES))
    assert meta_b["dominant_proto"] == 6
    assert meta_b["features"]["unique_src_ip_ratio"] < 0.05
    assert meta_b["features"]["src_ip_entropy_norm"] == 0.0
    assert pytest.approx(meta_b["features"]["tcp_syn_only_ratio"], abs=1e-4) == 0.5
    assert pytest.approx(meta_b["features"]["tcp_ack_or_est_ratio"], abs=1e-4) == 0.5
    assert meta_b["features"]["pkt_len_std"] > 0.0


def test_build_spoofed_tcp_syn_frame_checksums() -> None:
    src_mac = mac_to_bytes("00:00:00:00:00:02")
    dst_mac = mac_to_bytes("00:00:00:00:00:03")
    src_ip = struct.unpack("!I", socket.inet_aton("10.2.3.4"))[0]
    dst_ip = struct.unpack("!I", socket.inet_aton("10.0.0.3"))[0]

    frame = build_spoofed_tcp_syn_frame(src_mac, dst_mac, src_ip, dst_ip, 44444, 8088, seq_num=999, ip_id=3)
    assert len(frame) == 14 + 20 + 20
    assert ipv4_checksum(frame[14:34]) == 0

    tcp_hdr = frame[34:54]
    pseudo = struct.pack("!IIBBH", src_ip, dst_ip, 0, 6, len(tcp_hdr))
    assert ipv4_checksum(pseudo + tcp_hdr) == 0
    assert tcp_hdr[13] == 0x02  # SYN flag only


def test_async_stage2_worker_ipc_roundtrip(tmp_path: Path) -> None:
    rng = np.random.default_rng(42)
    X = np.vstack([
        rng.normal(loc=0.0, scale=0.2, size=(40, len(WINDOW_FEATURE_NAMES))),
        rng.normal(loc=5.0, scale=0.2, size=(40, len(WINDOW_FEATURE_NAMES))),
    ]).astype(np.float32)
    y = np.array([0] * 40 + [1] * 40)
    clf = LogisticRegression().fit(X, y)
    model_path = tmp_path / "dummy_stage2.joblib"
    joblib.dump({"model": clf, "features": WINDOW_FEATURE_NAMES}, model_path)

    worker = AsyncStage2Worker(str(model_path), pin_core=None, max_batch_size=8, attack_threshold=0.5)
    try:
        wpid = worker.start(timeout_s=15.0)
        assert wpid > 0
        assert worker.submit_nonblocking(1, 1, np.zeros((1, len(WINDOW_FEATURE_NAMES)), dtype=np.float32), 6, "10.0.0.3")
        assert worker.submit_nonblocking(1, 2, np.full((1, len(WINDOW_FEATURE_NAMES)), 5.0, dtype=np.float32), 17, "10.0.0.3")

        decisions = []
        deadline = time.monotonic() + 5.0
        while len(decisions) < 2 and time.monotonic() < deadline:
            decisions.extend(worker.poll_decisions())
            time.sleep(0.05)

        assert len(decisions) == 2
        by_port = {d["in_port"]: d for d in decisions}
        assert by_port[1]["is_attack"] is False
        assert by_port[2]["is_attack"] is True
        assert by_port[2]["dominant_proto"] == 17
    finally:
        worker.stop()
