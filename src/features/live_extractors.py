"""Live SDN flow feature extractors across observability tiers (T1a lightweight vs. T3 CIC-style).

Designed for honest, real-time component profiling inside os-ken:
- LiveT1aExtractor: O(1) unidirectional OpenFlow counter state -> 6 features.
- LiveT3CICExtractor: Stateful bidirectional packet-history statistics mimicking CICFlowMeter -> 65 features.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

import numpy as np


@dataclass(slots=True)
class _T1aFlowState:
    first_ts_ns: int
    last_ts_ns: int
    fwd_pkts: int
    fwd_bytes: int


class LiveT1aExtractor:
    """Lightweight O(1) unidirectional OpenFlow-native 6-feature extractor.

    Output order strictly matches TIER_1A_UNIDIRECTIONAL_OF:
    [Protocol, Flow Duration (us), Tot Fwd Pkts, TotLen Fwd Pkts, Fwd Pkts/s, Fwd Pkt Len Mean]
    """

    def __init__(self, max_flows: int = 20000) -> None:
        self.max_flows = max_flows
        self.flows: OrderedDict[tuple[Any, ...], _T1aFlowState] = OrderedDict()
        self._buf = np.empty((1, 6), dtype=np.float32)

    def reset(self) -> None:
        self.flows.clear()

    def extract(
        self,
        flow_key: tuple[str, str, int, int, int],
        pkt_len: int,
        now_ns: int,
    ) -> np.ndarray:
        proto = flow_key[4]
        st = self.flows.get(flow_key)
        if st is None:
            if len(self.flows) >= self.max_flows:
                self.flows.popitem(last=False)
            st = _T1aFlowState(first_ts_ns=now_ns, last_ts_ns=now_ns, fwd_pkts=1, fwd_bytes=pkt_len)
            self.flows[flow_key] = st
            dur_us = 1.0
        else:
            st.last_ts_ns = now_ns
            st.fwd_pkts += 1
            st.fwd_bytes += pkt_len
            dur_us = max(1.0, (st.last_ts_ns - st.first_ts_ns) / 1_000.0)

        fwd_pps = (st.fwd_pkts * 1_000_000.0) / dur_us
        fwd_mean = st.fwd_bytes / st.fwd_pkts

        buf = self._buf
        buf[0, 0] = float(proto)
        buf[0, 1] = dur_us
        buf[0, 2] = float(st.fwd_pkts)
        buf[0, 3] = float(st.fwd_bytes)
        buf[0, 4] = fwd_pps
        buf[0, 5] = fwd_mean
        return buf


@dataclass
class _T3FlowState:
    first_ts_ns: int
    last_ts_ns: int
    fwd_src: str
    all_ts_us: list[float] = field(default_factory=list)
    fwd_ts_us: list[float] = field(default_factory=list)
    bwd_ts_us: list[float] = field(default_factory=list)
    fwd_lens: list[int] = field(default_factory=list)
    bwd_lens: list[int] = field(default_factory=list)
    fwd_hdr_bytes: int = 0
    bwd_hdr_bytes: int = 0
    flag_counts: dict[str, int] = field(
        default_factory=lambda: {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "BWD_PSH": 0, "BWD_URG": 0}
    )
    init_bwd_win: int = -1


def _basic_stats(arr: list[float] | list[int]) -> tuple[float, float, float, float, float]:
    """Return (sum, mean, std, max, min) for a list of numeric observations."""
    n = len(arr)
    if n == 0:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    a = np.asarray(arr, dtype=np.float64)
    return float(a.sum()), float(a.mean()), float(a.std(ddof=0)), float(a.max()), float(a.min())


def _iats(ts_list: list[float]) -> list[float]:
    if len(ts_list) < 2:
        return []
    return [ts_list[i] - ts_list[i - 1] for i in range(1, len(ts_list))]


class LiveT3CICExtractor:
    """Stateful bidirectional CICFlowMeter-style extractor producing a 65-feature vector.

    Accurately reflects the real CPU and state-maintenance work required to compute
    per-packet bidirectional length, IAT, flag, header, and active/idle statistics in Python
    on the controller hot path.
    """

    def __init__(self, feature_names: list[str], max_flows: int = 20000, max_pkts_per_flow: int = 64) -> None:
        self.feature_names = list(feature_names)
        self.max_flows = max_flows
        self.max_pkts_per_flow = max_pkts_per_flow
        self.flows: OrderedDict[tuple[Any, ...], _T3FlowState] = OrderedDict()

    def reset(self) -> None:
        self.flows.clear()

    def extract(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: int,
        pkt_len: int,
        hdr_len: int,
        tcp_flags: int,
        tcp_window: int,
        now_ns: int,
    ) -> np.ndarray:
        # Canonical bidirectional key
        if (src_ip, src_port) <= (dst_ip, dst_port):
            bidir_key = (src_ip, src_port, dst_ip, dst_port, proto)
        else:
            bidir_key = (dst_ip, dst_port, src_ip, src_port, proto)

        ts_us = now_ns / 1_000.0
        st = self.flows.get(bidir_key)
        if st is None:
            if len(self.flows) >= self.max_flows:
                self.flows.popitem(last=False)
            st = _T3FlowState(first_ts_ns=now_ns, last_ts_ns=now_ns, fwd_src=src_ip)
            self.flows[bidir_key] = st
        else:
            st.last_ts_ns = now_ns

        is_fwd = src_ip == st.fwd_src
        if len(st.all_ts_us) < self.max_pkts_per_flow:
            st.all_ts_us.append(ts_us)
        if is_fwd:
            if len(st.fwd_ts_us) < self.max_pkts_per_flow:
                st.fwd_ts_us.append(ts_us)
                st.fwd_lens.append(pkt_len)
            st.fwd_hdr_bytes += hdr_len
        else:
            if len(st.bwd_ts_us) < self.max_pkts_per_flow:
                st.bwd_ts_us.append(ts_us)
                st.bwd_lens.append(pkt_len)
            st.bwd_hdr_bytes += hdr_len
            if st.init_bwd_win < 0:
                st.init_bwd_win = tcp_window

        if tcp_flags:
            if tcp_flags & 0x01:
                st.flag_counts["FIN"] += 1
            if tcp_flags & 0x02:
                st.flag_counts["SYN"] += 1
            if tcp_flags & 0x04:
                st.flag_counts["RST"] += 1
            if tcp_flags & 0x08:
                st.flag_counts["PSH"] += 1
                if not is_fwd:
                    st.flag_counts["BWD_PSH"] += 1
            if tcp_flags & 0x10:
                st.flag_counts["ACK"] += 1
            if tcp_flags & 0x20:
                st.flag_counts["URG"] += 1
                if not is_fwd:
                    st.flag_counts["BWD_URG"] += 1

        dur_us = max(1.0, (st.last_ts_ns - st.first_ts_ns) / 1_000.0)
        tot_fwd = len(st.fwd_lens)
        tot_bwd = len(st.bwd_lens)
        tot_pkts = max(1, tot_fwd + tot_bwd)

        fwd_sum, fwd_mean, fwd_std, fwd_max, fwd_min = _basic_stats(st.fwd_lens)
        bwd_sum, bwd_mean, bwd_std, bwd_max, bwd_min = _basic_stats(st.bwd_lens)
        all_lens = st.fwd_lens + st.bwd_lens
        all_sum, all_mean, all_std, all_max, all_min = _basic_stats(all_lens)

        flow_iat_tot, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _basic_stats(_iats(st.all_ts_us))
        fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _basic_stats(_iats(st.fwd_ts_us))
        bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _basic_stats(_iats(st.bwd_ts_us))

        # Active/Idle bursts (5 s idle threshold per CICFlowMeter convention)
        all_iats = _iats(st.all_ts_us)
        idle_vals = [x for x in all_iats if x >= 5_000_000.0]
        active_vals = [x for x in all_iats if x < 5_000_000.0]
        _, act_mean, act_std, act_max, act_min = _basic_stats(active_vals)
        _, idl_mean, idl_std, idl_max, idl_min = _basic_stats(idle_vals)

        feat_map: dict[str, float] = {
            "Protocol": float(proto),
            "Flow Duration": dur_us,
            "Tot Fwd Pkts": float(tot_fwd),
            "Tot Bwd Pkts": float(tot_bwd),
            "TotLen Fwd Pkts": fwd_sum,
            "TotLen Bwd Pkts": bwd_sum,
            "Fwd Pkt Len Max": fwd_max,
            "Fwd Pkt Len Min": fwd_min,
            "Fwd Pkt Len Mean": fwd_mean,
            "Fwd Pkt Len Std": fwd_std,
            "Bwd Pkt Len Max": bwd_max,
            "Bwd Pkt Len Min": bwd_min,
            "Bwd Pkt Len Mean": bwd_mean,
            "Bwd Pkt Len Std": bwd_std,
            "Flow Byts/s": (all_sum * 1_000_000.0) / dur_us,
            "Flow Pkts/s": (tot_pkts * 1_000_000.0) / dur_us,
            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            "Fwd IAT Tot": fwd_iat_tot,
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Tot": bwd_iat_tot,
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            "Bwd PSH Flags": float(st.flag_counts["BWD_PSH"]),
            "Bwd URG Flags": float(st.flag_counts["BWD_URG"]),
            "Fwd Header Len": float(st.fwd_hdr_bytes),
            "Bwd Header Len": float(st.bwd_hdr_bytes),
            "Fwd Pkts/s": (tot_fwd * 1_000_000.0) / dur_us,
            "Bwd Pkts/s": (tot_bwd * 1_000_000.0) / dur_us,
            "Pkt Len Min": all_min,
            "Pkt Len Max": all_max,
            "Pkt Len Mean": all_mean,
            "Pkt Len Std": all_std,
            "Pkt Len Var": all_std * all_std,
            "FIN Flag Cnt": float(st.flag_counts["FIN"]),
            "SYN Flag Cnt": float(st.flag_counts["SYN"]),
            "RST Flag Cnt": float(st.flag_counts["RST"]),
            "PSH Flag Cnt": float(st.flag_counts["PSH"]),
            "ACK Flag Cnt": float(st.flag_counts["ACK"]),
            "URG Flag Cnt": float(st.flag_counts["URG"]),
            "Down/Up Ratio": float(tot_bwd / max(1, tot_fwd)),
            "Pkt Size Avg": all_sum / tot_pkts,
            "Fwd Seg Size Avg": fwd_mean,
            "Bwd Seg Size Avg": bwd_mean,
            "Subflow Fwd Pkts": float(tot_fwd),
            "Subflow Fwd Byts": fwd_sum,
            "Subflow Bwd Pkts": float(tot_bwd),
            "Subflow Bwd Byts": bwd_sum,
            "Init Bwd Win Byts": float(st.init_bwd_win),
            "Fwd Act Data Pkts": float(sum(1 for l in st.fwd_lens if l > hdr_len)),
            "Active Mean": act_mean,
            "Active Std": act_std,
            "Active Max": act_max,
            "Active Min": act_min,
            "Idle Mean": idl_mean,
            "Idle Std": idl_std,
            "Idle Max": idl_max,
            "Idle Min": idl_min,
        }
        return np.array([[feat_map.get(name, 0.0) for name in self.feature_names]], dtype=np.float32)
