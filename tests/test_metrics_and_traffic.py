"""Unit tests for metrics summarization, non-overwrite guards, and raw packet construction."""

from __future__ import annotations

import socket
import struct
from pathlib import Path

import pytest

from evaluation.metrics import ensure_non_overwrite, summarize_distribution
from evaluation.traffic_gen import build_spoofed_udp_frame, ipv4_checksum, mac_to_bytes


def test_summarize_distribution_empty() -> None:
    res = summarize_distribution([])
    assert res["count"] == 0
    assert res["p50"] is None
    assert res["p99"] is None


def test_summarize_distribution_percentiles() -> None:
    values = list(range(1, 101))
    res = summarize_distribution(values)
    assert res["count"] == 100
    assert res["min"] == 1.0
    assert res["max"] == 100.0
    assert pytest.approx(res["p50"], abs=1e-6) == 50.5
    assert pytest.approx(res["p95"], abs=1e-6) == 95.05
    assert pytest.approx(res["p99"], abs=1e-6) == 99.01


def test_ensure_non_overwrite_raises(tmp_path: Path) -> None:
    existing = tmp_path / "EXP-0001.json"
    existing.write_text("{}", encoding="utf-8")
    with pytest.raises(FileExistsError):
        ensure_non_overwrite([existing])


def test_build_spoofed_udp_frame_valid_headers() -> None:
    src_mac = mac_to_bytes("00:00:00:00:00:02")
    dst_mac = mac_to_bytes("00:00:00:00:00:03")
    src_ip = struct.unpack("!I", socket.inet_aton("10.1.2.3"))[0]
    dst_ip = struct.unpack("!I", socket.inet_aton("10.0.0.3"))[0]
    payload = b"X" * 64

    frame = build_spoofed_udp_frame(src_mac, dst_mac, src_ip, dst_ip, 54321, 9999, payload, ip_id=7)
    assert len(frame) == 14 + 20 + 8 + 64
    assert frame[0:6] == dst_mac
    assert frame[6:12] == src_mac
    assert frame[12:14] == b"\x08\x00"

    # IPv4 checksum over header including checksum field must evaluate to 0
    ip_hdr = frame[14:34]
    assert ipv4_checksum(ip_hdr) == 0

    udp_src, udp_dst, udp_len, udp_csum = struct.unpack("!HHHH", frame[34:42])
    assert udp_src == 54321
    assert udp_dst == 9999
    assert udp_len == 72
    assert udp_csum == 0
    assert frame[42:] == payload
