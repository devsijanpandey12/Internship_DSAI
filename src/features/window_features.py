"""O(1)-update windowed OpenFlow control-plane feature aggregation for Stage-1/Stage-2 defense.

Strictly IP-value-agnostic and port-value-agnostic: captures distributional and protocol
invariants over short tumbling windows per (dpid, in_port) so the detector cannot memorize
lab IP addresses or service ports and generalizes across UDP and TCP SYN floods vs.
legitimate bidirectional TCP flash crowds.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

import numpy as np

WINDOW_FEATURE_NAMES = [
    "packet_in_rate_pps",
    "unique_src_ip_ratio",
    "src_ip_entropy_norm",
    "unique_src_port_ratio",
    "dst_ip_concentration",
    "udp_ratio",
    "tcp_syn_only_ratio",
    "tcp_ack_or_est_ratio",
    "pkt_len_mean",
    "pkt_len_std",
]


def normalized_shannon_entropy(counts: Counter[Any], total: int) -> float:
    """Compute Shannon entropy normalized to [0, 1] by log2(total)."""
    if total <= 1 or len(counts) <= 1:
        return 0.0
    h = 0.0
    for c in counts.values():
        p = c / total
        if p > 0.0:
            h -= p * math.log2(p)
    max_h = math.log2(total)
    return float(min(1.0, max(0.0, h / max_h))) if max_h > 0 else 0.0


class PortWindowAccumulator:
    """Lightweight per-(dpid, in_port) accumulator over a short tumbling window (e.g., 250 ms)."""

    __slots__ = (
        "count",
        "src_ips",
        "src_ports",
        "dst_ips",
        "protos",
        "udp_count",
        "tcp_syn_only_count",
        "tcp_ack_count",
        "len_sum",
        "len_sq_sum",
    )

    def __init__(self) -> None:
        self.count = 0
        self.src_ips: Counter[str] = Counter()
        self.src_ports: Counter[int] = Counter()
        self.dst_ips: Counter[str] = Counter()
        self.protos: Counter[int] = Counter()
        self.udp_count = 0
        self.tcp_syn_only_count = 0
        self.tcp_ack_count = 0
        self.len_sum = 0.0
        self.len_sq_sum = 0.0

    def record(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        proto: int,
        tcp_flags: int,
        pkt_len: int,
    ) -> None:
        """O(1) per-Packet-In counter update."""
        self.count += 1
        self.src_ips[src_ip] += 1
        self.src_ports[src_port] += 1
        self.dst_ips[dst_ip] += 1
        self.protos[proto] += 1
        if proto == 17:
            self.udp_count += 1
        elif proto == 6:
            has_syn = bool(tcp_flags & 0x02)
            has_ack = bool(tcp_flags & 0x10)
            if has_syn and not has_ack:
                self.tcp_syn_only_count += 1
            elif has_ack:
                self.tcp_ack_count += 1
        fl = float(pkt_len)
        self.len_sum += fl
        self.len_sq_sum += fl * fl

    def finalize_and_reset(self, window_s: float) -> tuple[np.ndarray, dict[str, Any]]:
        """Compute the 10-feature float32 vector + metadata and reset counters cleanly."""
        n = self.count
        if n == 0:
            vec = np.zeros((1, len(WINDOW_FEATURE_NAMES)), dtype=np.float32)
            return vec, {"count": 0, "dominant_proto": 0, "dominant_dst_ip": ""}

        dur = max(window_s, 1e-3)
        rate_pps = n / dur
        uniq_src_ratio = len(self.src_ips) / n
        src_ent = normalized_shannon_entropy(self.src_ips, n)
        uniq_port_ratio = len(self.src_ports) / n
        top_dst_ip, top_dst_cnt = self.dst_ips.most_common(1)[0]
        dst_conc = top_dst_cnt / n
        udp_ratio = self.udp_count / n
        syn_only_ratio = self.tcp_syn_only_count / n
        ack_ratio = self.tcp_ack_count / n
        mean_len = self.len_sum / n
        var_len = max(0.0, (self.len_sq_sum / n) - (mean_len * mean_len))
        std_len = math.sqrt(var_len)
        dom_proto = int(self.protos.most_common(1)[0][0])

        vec = np.array(
            [[
                rate_pps,
                uniq_src_ratio,
                src_ent,
                uniq_port_ratio,
                dst_conc,
                udp_ratio,
                syn_only_ratio,
                ack_ratio,
                mean_len,
                std_len,
            ]],
            dtype=np.float32,
        )
        meta = {
            "count": n,
            "packet_in_rate_pps": rate_pps,
            "dominant_proto": dom_proto,
            "dominant_dst_ip": top_dst_ip,
            "features": {k: float(vec[0, i]) for i, k in enumerate(WINDOW_FEATURE_NAMES)},
        }

        # Reset in-place
        self.count = 0
        self.src_ips.clear()
        self.src_ports.clear()
        self.dst_ips.clear()
        self.protos.clear()
        self.udp_count = 0
        self.tcp_syn_only_count = 0
        self.tcp_ack_count = 0
        self.len_sum = 0.0
        self.len_sq_sum = 0.0
        return vec, meta
