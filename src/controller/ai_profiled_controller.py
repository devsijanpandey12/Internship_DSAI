"""Component-profiled os-ken OpenFlow 1.3 controller for Phase 4B (EXP-0007).

Decomposes every Packet-In handler execution into exact microsecond sub-components:
  1. base_ofp_ms: Packet parsing, MAC learning, match building, FlowMod + PacketOut dispatch.
  2. feature_extract_ms: Live feature extraction (none / T1a 6-feat / T3 65-feat CIC-style).
  3. model_infer_ms: Synchronous single-sample (batch=1) ML inference (none / LR / LGBM / XGB / RF).
  4. total_handler_ms: Full synchronous Packet-In execution time.
  5. event_loop_lag_ms: Cooperative eventlet heartbeat lag exposing GIL/event-loop starvation.

Important: In EXP-0007 (Baseline B/C overhead profiling), mitigation dropping is intentionally
disabled (observe-only mode) so all 8 pipelines face the EXACT SAME Packet-In arrival load
for fair component attribution. Active mitigation is evaluated in Phase 5.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import eventlet
import joblib
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import ethernet, ether_types, ipv4, packet, tcp, udp
from os_ken.ofproto import ofproto_v1_3

from evaluation.metrics import summarize_distribution
from features.live_extractors import LiveT1aExtractor, LiveT3CICExtractor
from models.offline_baselines import set_single_thread_inference


class ComponentProfiledAISwitch13(app_manager.OSKenApp):
    """Reactive OpenFlow 1.3 switch with switchable live feature/ML pipeline and stage timers."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.telemetry_port = int(os.environ.get("SDN_TELEMETRY_PORT", "18080"))
        self.flow_idle_timeout = int(os.environ.get("SDN_FLOW_IDLE_TIMEOUT", "15"))
        self.flow_hard_timeout = int(os.environ.get("SDN_FLOW_HARD_TIMEOUT", "30"))
        self.heartbeat_interval_s = float(os.environ.get("SDN_HEARTBEAT_INTERVAL_MS", "50")) / 1000.0

        self.mac_to_port: dict[int, dict[str, int]] = {}
        self.datapaths: dict[int, Any] = {}

        # Active detection pipeline configuration (hot-swappable between trials via RPC)
        self.pipeline_name = "Baseline_A_NoAI"
        self.extractor_mode = "none"  # "none" | "t1a" | "t3"
        self.t1a_extractor = LiveT1aExtractor()
        self.t3_extractor: LiveT3CICExtractor | None = None
        self.active_model: Any = None
        self.model_cache: dict[str, dict[str, Any]] = {}

        # Per-phase in-memory stage latency telemetry
        self.phase_name = "init"
        self.phase_start_mono_s = time.monotonic()
        self.total_handler_ms: list[float] = []
        self.base_ofp_ms: list[float] = []
        self.feature_extract_ms: list[float] = []
        self.model_infer_ms: list[float] = []
        self.event_loop_lag_ms: list[float] = []

        self.packet_in_total = 0
        self.ipv4_evaluated_total = 0
        self.predicted_attack_total = 0
        self.predicted_normal_total = 0
        self.flow_mod_total = 0
        self.table_full_errors = 0

        self._heartbeat_thread = hub.spawn(self._heartbeat_loop)
        self._rpc_thread = hub.spawn(self._telemetry_rpc_server)
        self.logger.info("ComponentProfiledAISwitch13 ready (rpc_port=%d)", self.telemetry_port)

    def _configure_pipeline(self, name: str, extractor_mode: str, model_path: str | None, feature_names: list[str] | None) -> None:
        self.pipeline_name = name
        self.extractor_mode = extractor_mode
        self.t1a_extractor.reset()
        self.active_model = None
        self.t3_extractor = None

        if extractor_mode == "t3":
            if not feature_names:
                raise ValueError("T3 extractor requires feature_names")
            self.t3_extractor = LiveT3CICExtractor(feature_names=feature_names)

        if model_path:
            if model_path not in self.model_cache:
                loaded = joblib.load(model_path)
                set_single_thread_inference(loaded["model"])
                self.model_cache[model_path] = loaded
            bundle = self.model_cache[model_path]
            self.active_model = bundle["model"]
            if extractor_mode == "t3" and self.t3_extractor is None:
                self.t3_extractor = LiveT3CICExtractor(feature_names=bundle["features"])
            # Warm up model once off the measurement path so JIT/threadpool init isn't counted
            import numpy as np

            n_f = len(bundle["features"])
            self.active_model.predict_proba(np.zeros((1, n_f), dtype=np.float32))

        self.logger.info(
            "Configured pipeline=%s (extractor=%s, model=%s)",
            self.pipeline_name,
            self.extractor_mode,
            model_path or "none",
        )

    def _reset_phase(self, phase_name: str) -> None:
        self.phase_name = phase_name
        self.phase_start_mono_s = time.monotonic()
        self.total_handler_ms = []
        self.base_ofp_ms = []
        self.feature_extract_ms = []
        self.model_infer_ms = []
        self.event_loop_lag_ms = []
        self.packet_in_total = 0
        self.ipv4_evaluated_total = 0
        self.predicted_attack_total = 0
        self.predicted_normal_total = 0
        self.flow_mod_total = 0
        self.table_full_errors = 0
        self.t1a_extractor.reset()
        if self.t3_extractor is not None:
            self.t3_extractor.reset()

    def _snapshot_phase(self) -> dict[str, Any]:
        elapsed_s = max(time.monotonic() - self.phase_start_mono_s, 1e-9)
        return {
            "phase_name": self.phase_name,
            "pipeline_name": self.pipeline_name,
            "elapsed_s": elapsed_s,
            "connected_dpids": sorted(self.datapaths.keys()),
            "packet_in_total": self.packet_in_total,
            "packet_in_rate_pps": self.packet_in_total / elapsed_s,
            "ipv4_evaluated_total": self.ipv4_evaluated_total,
            "predicted_attack_total": self.predicted_attack_total,
            "predicted_normal_total": self.predicted_normal_total,
            "flow_mod_total": self.flow_mod_total,
            "table_full_errors": self.table_full_errors,
            "total_handler_ms": summarize_distribution(self.total_handler_ms),
            "base_ofp_ms": summarize_distribution(self.base_ofp_ms),
            "feature_extract_ms": summarize_distribution(self.feature_extract_ms),
            "model_infer_ms": summarize_distribution(self.model_infer_ms),
            "event_loop_lag_ms": summarize_distribution(self.event_loop_lag_ms),
        }

    def _heartbeat_loop(self) -> None:
        expected = self.heartbeat_interval_s
        while True:
            t0 = time.perf_counter()
            hub.sleep(expected)
            actual = time.perf_counter() - t0
            self.event_loop_lag_ms.append(max(0.0, (actual - expected) * 1000.0))

    def _telemetry_rpc_server(self) -> None:
        server = eventlet.listen(("127.0.0.1", self.telemetry_port))
        while True:
            sock, _ = server.accept()
            hub.spawn(self._handle_rpc_client, sock)

    def _handle_rpc_client(self, sock: Any) -> None:
        try:
            with sock.makefile("rw", encoding="utf-8") as stream:
                line = stream.readline()
                if not line:
                    return
                req = json.loads(line)
                cmd = req.get("cmd")
                if cmd == "ping":
                    resp: dict[str, Any] = {
                        "ok": True,
                        "pid": os.getpid(),
                        "connected_dpids": sorted(self.datapaths.keys()),
                    }
                elif cmd == "configure_pipeline":
                    self._configure_pipeline(
                        name=str(req["name"]),
                        extractor_mode=str(req.get("extractor_mode", "none")),
                        model_path=req.get("model_path"),
                        feature_names=req.get("feature_names"),
                    )
                    resp = {"ok": True, "pipeline_name": self.pipeline_name}
                elif cmd == "reset_phase":
                    self._reset_phase(str(req.get("phase_name", "unnamed")))
                    resp = {"ok": True}
                elif cmd == "snapshot_phase":
                    resp = {"ok": True, "snapshot": self._snapshot_phase()}
                elif cmd == "reinstall_table_miss":
                    for dp in self.datapaths.values():
                        self._install_table_miss(dp)
                    resp = {"ok": True}
                else:
                    resp = {"ok": False, "error": f"unknown command: {cmd}"}
                stream.write(json.dumps(resp) + "\n")
                stream.flush()
        except Exception as exc:
            self.logger.warning("RPC error: %s", exc)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _install_table_miss(self, datapath: Any) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, cookie=0x0, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev: Any) -> None:
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})
        self._install_table_miss(datapath)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def error_msg_handler(self, ev: Any) -> None:
        msg = ev.msg
        if (
            msg.type == ofproto_v1_3.OFPET_FLOW_MOD_FAILED
            and msg.code == ofproto_v1_3.OFPFMFC_TABLE_FULL
        ):
            self.table_full_errors += 1

    def _add_flow(self, datapath: Any, priority: int, match: Any, actions: list[Any]) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=0x10,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=self.flow_idle_timeout,
            hard_timeout=self.flow_hard_timeout,
        )
        datapath.send_msg(mod)
        self.flow_mod_total += 1

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev: Any) -> None:
        t_start = time.perf_counter_ns()
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = datapath.id
        mac_table = self.mac_to_port.setdefault(dpid, {})
        mac_table[eth.src] = in_port
        out_port = mac_table.get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip_pkt = pkt.get_protocol(ipv4.ipv4) if eth.ethertype == ether_types.ETH_TYPE_IP else None
        tcp_pkt = pkt.get_protocol(tcp.tcp) if (ip_pkt and ip_pkt.proto == 6) else None
        udp_pkt = pkt.get_protocol(udp.udp) if (ip_pkt and ip_pkt.proto == 17) else None

        feat_ns = 0
        infer_ns = 0

        # Execute configured live feature extractor + synchronous ML model on IPv4 flows
        if ip_pkt is not None and self.extractor_mode != "none":
            self.ipv4_evaluated_total += 1
            src_port = tcp_pkt.src_port if tcp_pkt else (udp_pkt.src_port if udp_pkt else 0)
            dst_port = tcp_pkt.dst_port if tcp_pkt else (udp_pkt.dst_port if udp_pkt else 0)
            pkt_len = len(msg.data)

            t_f0 = time.perf_counter_ns()
            if self.extractor_mode == "t1a":
                x_vec = self.t1a_extractor.extract(
                    (ip_pkt.src, ip_pkt.dst, src_port, dst_port, ip_pkt.proto),
                    pkt_len=pkt_len,
                    now_ns=t_f0,
                )
            elif self.extractor_mode == "t3" and self.t3_extractor is not None:
                hdr_len = (ip_pkt.header_length * 4) + ((tcp_pkt.offset * 4) if tcp_pkt else (8 if udp_pkt else 0))
                tcp_flags = int(tcp_pkt.bits) if tcp_pkt else 0
                tcp_win = int(tcp_pkt.window_size) if tcp_pkt else -1
                x_vec = self.t3_extractor.extract(
                    src_ip=ip_pkt.src,
                    dst_ip=ip_pkt.dst,
                    src_port=src_port,
                    dst_port=dst_port,
                    proto=ip_pkt.proto,
                    pkt_len=pkt_len,
                    hdr_len=hdr_len,
                    tcp_flags=tcp_flags,
                    tcp_window=tcp_win,
                    now_ns=t_f0,
                )
            else:
                x_vec = None
            t_f1 = time.perf_counter_ns()
            feat_ns = t_f1 - t_f0

            if self.active_model is not None and x_vec is not None:
                t_m0 = time.perf_counter_ns()
                prob = float(self.active_model.predict_proba(x_vec)[0, 1])
                t_m1 = time.perf_counter_ns()
                infer_ns = t_m1 - t_m0
                if prob >= 0.5:
                    self.predicted_attack_total += 1
                else:
                    self.predicted_normal_total += 1

        # Build OpenFlow 5-tuple match & install forwarding rule
        if out_port != ofproto.OFPP_FLOOD:
            if ip_pkt is not None and tcp_pkt is not None:
                match = parser.OFPMatch(
                    in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst, ip_proto=6,
                    tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port,
                )
            elif ip_pkt is not None and udp_pkt is not None:
                match = parser.OFPMatch(
                    in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst, ip_proto=17,
                    udp_src=udp_pkt.src_port, udp_dst=udp_pkt.dst_port,
                )
            elif ip_pkt is not None:
                match = parser.OFPMatch(
                    in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst, ip_proto=ip_pkt.proto,
                )
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            self._add_flow(datapath, priority=10, match=match, actions=actions)

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

        t_end = time.perf_counter_ns()
        total_ns = t_end - t_start
        base_ns = max(0, total_ns - feat_ns - infer_ns)

        self.total_handler_ms.append(total_ns / 1_000_000.0)
        self.base_ofp_ms.append(base_ns / 1_000_000.0)
        self.feature_extract_ms.append(feat_ns / 1_000_000.0)
        self.model_infer_ms.append(infer_ns / 1_000_000.0)
        self.packet_in_total += 1
