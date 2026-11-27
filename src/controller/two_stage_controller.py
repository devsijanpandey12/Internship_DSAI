"""Mode-switchable OpenFlow 1.3 controller for Phase 5 experiments (EXP-0008 & EXP-0009).

Supported modes (hot-swappable between trials via loopback JSON RPC):
  - collector:                             Records 250 ms windowed OpenFlow telemetry (no drops)
  - A0_Baseline_NoAI:                      Pure reactive 5-tuple OpenFlow 1.3 forwarding
  - A1_Sync_Light_LGBM:                    Synchronous batch=1 T1a + LightGBM inside Packet-In
  - A2_Decoupled_Async_WindowML:           Out-of-process Stage-2 windowed LightGBM (no gate/guard)
  - A3_TwoStage_Gate_Decoupled_TableGuard: Stage-1 O(1) gate + Selective Flow-Table Guard +
                                           out-of-process Stage-2 windowed LightGBM
  - A4_Static_Rate_Threshold:              Naive non-AI rate limiter (drops any port > gate_pps)
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import eventlet
import joblib
import numpy as np
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import ethernet, ether_types, ipv4, packet, tcp, udp
from os_ken.ofproto import ofproto_v1_3

from evaluation.metrics import summarize_distribution
from features.live_extractors import LiveT1aExtractor
from features.window_features import PortWindowAccumulator
from mitigation.async_worker import AsyncStage2Worker
from models.offline_baselines import set_single_thread_inference


class TwoStageDefenseSwitch13(app_manager.OSKenApp):
    """Unified SDN controller enabling controlled single-variable Phase 5 ablations."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.telemetry_port = int(os.environ.get("SDN_TELEMETRY_PORT", "18080"))
        self.flow_idle_timeout = int(os.environ.get("SDN_FLOW_IDLE_TIMEOUT", "15"))
        self.flow_hard_timeout = int(os.environ.get("SDN_FLOW_HARD_TIMEOUT", "30"))
        self.heartbeat_interval_s = float(os.environ.get("SDN_HEARTBEAT_INTERVAL_MS", "50")) / 1000.0
        self.window_interval_s = float(os.environ.get("SDN_WINDOW_INTERVAL_MS", "250")) / 1000.0
        self.worker_pin_core = int(os.environ.get("SDN_WORKER_CORE", "8"))

        self.mac_to_port: dict[int, dict[str, int]] = {}
        self.datapaths: dict[int, Any] = {}

        # Active architecture settings
        self.mode = "A0_Baseline_NoAI"
        self.gate_pps = 30.0
        self.mitigation_hard_timeout_s = 5
        self.edge_ports: dict[int, set[int]] = {1: {1, 2}}  # Access ports on edge switch s1

        # Sync Baseline B (A1) state
        self.t1a_extractor = LiveT1aExtractor()
        self.sync_model: Any = None
        self._sync_model_cache: dict[str, Any] = {}

        # Decoupled Stage-2 (A2/A3) worker state
        self.async_worker: AsyncStage2Worker | None = None
        self.async_model_path: str | None = None

        # Per-port O(1) window accumulators & fast-path guard state
        self.port_windows: dict[tuple[int, int], PortWindowAccumulator] = {}
        self.port_recent_rate_pps: dict[tuple[int, int], float] = {}
        self.port_burst_count_current: dict[tuple[int, int], int] = {}
        self.port_cleared_benign_until: dict[tuple[int, int], float] = {}
        self.port_mitigated_until: dict[tuple[int, int], float] = {}
        self.port_first_burst_ns: dict[tuple[int, int], int] = {}

        # Per-phase telemetry
        self.phase_name = "init"
        self.phase_start_mono_s = time.monotonic()
        self.total_handler_ms: list[float] = []
        self.event_loop_lag_ms: list[float] = []
        self.worker_infer_ms: list[float] = []
        self.detection_to_mitigation_ms: list[float] = []
        self.collected_windows: list[dict[str, Any]] = []

        self.packet_in_total = 0
        self.flow_mod_total = 0
        self.table_guard_bypassed_flowmods = 0
        self.table_full_errors = 0
        self.stage1_gate_triggers = 0
        self.stage2_ipc_submitted = 0
        self.stage2_decisions_attack = 0
        self.stage2_decisions_benign = 0
        self.mitigation_rules_installed = 0
        self.mitigations_by_port: dict[str, int] = {}

        self._heartbeat_thread = hub.spawn(self._heartbeat_loop)
        self._window_thread = hub.spawn(self._window_tick_loop)
        self._rpc_thread = hub.spawn(self._telemetry_rpc_server)
        self.logger.info("TwoStageDefenseSwitch13 ready (rpc_port=%d, window=%.0fms)", self.telemetry_port, self.window_interval_s * 1000)

    def _is_edge_port(self, dpid: int, in_port: int) -> bool:
        return in_port in self.edge_ports.get(dpid, set())

    def _configure(self, req: dict[str, Any]) -> dict[str, Any]:
        self.mode = str(req.get("mode", "A0_Baseline_NoAI"))
        self.gate_pps = float(req.get("gate_pps", 30.0))
        self.mitigation_hard_timeout_s = int(req.get("mitigation_hard_timeout_s", 5))
        if "window_interval_ms" in req:
            self.window_interval_s = float(req["window_interval_ms"]) / 1000.0
        if "edge_ports" in req:
            self.edge_ports = {int(k): set(int(p) for p in v) for k, v in req["edge_ports"].items()}

        # Configure synchronous model for A1
        self.sync_model = None
        sync_path = req.get("sync_model_path")
        if self.mode == "A1_Sync_Light_LGBM" and sync_path:
            if sync_path not in self._sync_model_cache:
                b = joblib.load(sync_path)
                m = b["model"]
                set_single_thread_inference(m)
                m.predict_proba(np.zeros((1, len(b["features"])), dtype=np.float32))
                self._sync_model_cache[sync_path] = m
            self.sync_model = self._sync_model_cache[sync_path]

        # Configure out-of-process Stage-2 worker for A2/A3
        stage2_path = req.get("stage2_model_path")
        if self.mode in ("A2_Decoupled_Async_WindowML", "A3_TwoStage_Gate_Decoupled_TableGuard"):
            if not stage2_path:
                raise ValueError(f"Mode {self.mode} requires stage2_model_path")
            if self.async_worker is None or self.async_model_path != stage2_path:
                if self.async_worker is not None:
                    self.async_worker.stop()
                self.async_worker = AsyncStage2Worker(
                    model_path=stage2_path,
                    pin_core=self.worker_pin_core,
                    max_batch_size=32,
                    attack_threshold=float(req.get("attack_threshold", 0.5)),
                )
                self.async_worker.start(timeout_s=20.0)
                self.async_model_path = stage2_path

        self.logger.info(
            "Configured mode=%s (gate_pps=%.1f, worker_pid=%s)",
            self.mode,
            self.gate_pps,
            self.async_worker.worker_pid if self.async_worker else None,
        )
        return {
            "ok": True,
            "mode": self.mode,
            "worker_pid": self.async_worker.worker_pid if self.async_worker else None,
        }

    def _reset_phase(self, phase_name: str) -> None:
        self.phase_name = phase_name
        self.phase_start_mono_s = time.monotonic()
        self.total_handler_ms = []
        self.event_loop_lag_ms = []
        self.worker_infer_ms = []
        self.detection_to_mitigation_ms = []
        self.collected_windows = []

        self.packet_in_total = 0
        self.flow_mod_total = 0
        self.table_guard_bypassed_flowmods = 0
        self.table_full_errors = 0
        self.stage1_gate_triggers = 0
        self.stage2_ipc_submitted = 0
        self.stage2_decisions_attack = 0
        self.stage2_decisions_benign = 0
        self.mitigation_rules_installed = 0
        self.mitigations_by_port = {}

        self.t1a_extractor.reset()
        self.port_windows.clear()
        self.port_recent_rate_pps.clear()
        self.port_burst_count_current.clear()
        self.port_cleared_benign_until.clear()
        self.port_mitigated_until.clear()
        self.port_first_burst_ns.clear()

        if self.async_worker is not None:
            self.async_worker.poll_decisions(max_items=512)

    def _snapshot_phase(self, include_windows: bool = False) -> dict[str, Any]:
        elapsed_s = max(time.monotonic() - self.phase_start_mono_s, 1e-9)
        snap: dict[str, Any] = {
            "phase_name": self.phase_name,
            "mode": self.mode,
            "elapsed_s": elapsed_s,
            "connected_dpids": sorted(self.datapaths.keys()),
            "worker_pid": self.async_worker.worker_pid if self.async_worker else None,
            "packet_in_total": self.packet_in_total,
            "packet_in_rate_pps": self.packet_in_total / elapsed_s,
            "flow_mod_total": self.flow_mod_total,
            "table_guard_bypassed_flowmods": self.table_guard_bypassed_flowmods,
            "table_full_errors": self.table_full_errors,
            "stage1_gate_triggers": self.stage1_gate_triggers,
            "stage2_ipc_submitted": self.stage2_ipc_submitted,
            "stage2_decisions_attack": self.stage2_decisions_attack,
            "stage2_decisions_benign": self.stage2_decisions_benign,
            "mitigation_rules_installed": self.mitigation_rules_installed,
            "mitigations_by_port": dict(self.mitigations_by_port),
            "total_handler_ms": summarize_distribution(self.total_handler_ms),
            "event_loop_lag_ms": summarize_distribution(self.event_loop_lag_ms),
            "worker_infer_ms": summarize_distribution(self.worker_infer_ms),
            "detection_to_mitigation_ms": summarize_distribution(self.detection_to_mitigation_ms),
        }
        if include_windows:
            snap["collected_windows"] = list(self.collected_windows)
        return snap

    def _heartbeat_loop(self) -> None:
        expected = self.heartbeat_interval_s
        while True:
            t0 = time.perf_counter()
            hub.sleep(expected)
            actual = time.perf_counter() - t0
            self.event_loop_lag_ms.append(max(0.0, (actual - expected) * 1000.0))

    def _install_mitigation_drop(self, dpid: int, in_port: int, ip_proto: int) -> None:
        dp = self.datapaths.get(dpid)
        if dp is None:
            return
        now_s = time.monotonic()
        key = (dpid, in_port)
        # Avoid re-installing redundant drop rules while active mitigation holds
        if self.port_mitigated_until.get(key, 0.0) > now_s + 0.5:
            return

        parser = dp.ofproto_parser
        if ip_proto in (6, 17):
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=ether_types.ETH_TYPE_IP,
                ip_proto=ip_proto,
            )
        else:
            match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP)

        # Empty instructions = OpenFlow 1.3 DROP action at priority=20 (> priority=10 forwarding)
        mod = parser.OFPFlowMod(
            datapath=dp,
            cookie=0x20,
            priority=20,
            match=match,
            instructions=[],
            hard_timeout=self.mitigation_hard_timeout_s,
        )
        dp.send_msg(mod)
        self.port_mitigated_until[key] = now_s + self.mitigation_hard_timeout_s
        self.mitigation_rules_installed += 1
        pkey = f"s{dpid}:p{in_port}"
        self.mitigations_by_port[pkey] = self.mitigations_by_port.get(pkey, 0) + 1

        if key in self.port_first_burst_ns:
            d2m = (time.perf_counter_ns() - self.port_first_burst_ns.pop(key)) / 1_000_000.0
            self.detection_to_mitigation_ms.append(d2m)

    def _window_tick_loop(self) -> None:
        """Periodic 250 ms telemetry flush, Stage-1 gating, and async Stage-2 decision polling."""
        last_tick = time.monotonic()
        while True:
            hub.sleep(self.window_interval_s)
            now_s = time.monotonic()
            actual_win = max(now_s - last_tick, 0.05)
            last_tick = now_s

            # 1. Drain any completed decisions from decoupled Stage-2 worker
            if self.async_worker is not None and self.mode in (
                "A2_Decoupled_Async_WindowML",
                "A3_TwoStage_Gate_Decoupled_TableGuard",
            ):
                for dec in self.async_worker.poll_decisions():
                    self.worker_infer_ms.append(float(dec["worker_infer_ms"]))
                    key = (int(dec["dpid"]), int(dec["in_port"]))
                    if dec["is_attack"]:
                        self.stage2_decisions_attack += 1
                        self._install_mitigation_drop(key[0], key[1], int(dec["dominant_proto"]))
                    else:
                        self.stage2_decisions_benign += 1
                        # Stage 2 confirmed legitimate flash crowd -> lift Flow-Table Guard for 2 s
                        self.port_cleared_benign_until[key] = now_s + 2.0
                        self.port_first_burst_ns.pop(key, None)

            # 2. Finalize tumbling window counters for all active edge ports
            for key, acc in list(self.port_windows.items()):
                dpid, in_port = key
                if acc.count == 0:
                    self.port_recent_rate_pps[key] = 0.0
                    self.port_burst_count_current[key] = 0
                    continue
                vec, meta = acc.finalize_and_reset(actual_win)
                rate_pps = float(meta["packet_in_rate_pps"])
                self.port_recent_rate_pps[key] = rate_pps
                self.port_burst_count_current[key] = 0

                if not self._is_edge_port(dpid, in_port):
                    continue

                if self.mode == "collector":
                    rec = {
                        "dpid": dpid,
                        "in_port": in_port,
                        "window_s": actual_win,
                        "count": int(meta["count"]),
                        "dominant_proto": int(meta["dominant_proto"]),
                        **meta["features"],
                    }
                    self.collected_windows.append(rec)
                elif self.mode == "A2_Decoupled_Async_WindowML":
                    # No Stage-1 gate: submits EVERY active window unconditionally to Stage 2
                    if self.async_worker is not None:
                        if self.async_worker.submit_nonblocking(
                            dpid, in_port, vec, int(meta["dominant_proto"]), str(meta["dominant_dst_ip"])
                        ):
                            self.stage2_ipc_submitted += 1
                elif self.mode == "A3_TwoStage_Gate_Decoupled_TableGuard":
                    # Stage-1 O(1) gate: 0% Stage-2 ML overhead unless port exceeds gate_pps
                    if rate_pps >= self.gate_pps:
                        self.stage1_gate_triggers += 1
                        if self.async_worker is not None:
                            if self.async_worker.submit_nonblocking(
                                dpid, in_port, vec, int(meta["dominant_proto"]), str(meta["dominant_dst_ip"])
                            ):
                                self.stage2_ipc_submitted += 1
                elif self.mode == "A4_Static_Rate_Threshold":
                    # Naive static threshold: blindly drops ANY port exceeding gate_pps (no AI!)
                    if rate_pps >= self.gate_pps:
                        self.stage1_gate_triggers += 1
                        self._install_mitigation_drop(dpid, in_port, int(meta["dominant_proto"]))

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
                        "worker_pid": self.async_worker.worker_pid if self.async_worker else None,
                        "connected_dpids": sorted(self.datapaths.keys()),
                    }
                elif cmd == "configure":
                    resp = self._configure(req)
                elif cmd == "reset_phase":
                    self._reset_phase(str(req.get("phase_name", "unnamed")))
                    resp = {"ok": True}
                elif cmd == "snapshot_phase":
                    resp = {
                        "ok": True,
                        "snapshot": self._snapshot_phase(include_windows=bool(req.get("include_windows", False))),
                    }
                elif cmd == "reinstall_table_miss":
                    for dp in self.datapaths.values():
                        self._install_table_miss(dp)
                    resp = {"ok": True}
                else:
                    resp = {"ok": False, "error": f"unknown cmd: {cmd}"}
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
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
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
        t0 = time.perf_counter_ns()
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

        suppress_flow_mod = False

        if ip_pkt is not None:
            src_port = tcp_pkt.src_port if tcp_pkt else (udp_pkt.src_port if udp_pkt else 0)
            dst_port = tcp_pkt.dst_port if tcp_pkt else (udp_pkt.dst_port if udp_pkt else 0)
            tcp_flags = int(tcp_pkt.bits) if tcp_pkt else 0
            pkt_len = len(msg.data)

            # A1: Synchronous batch=1 baseline (runs ML directly inside Packet-In hot path)
            if self.mode == "A1_Sync_Light_LGBM" and self.sync_model is not None:
                x_vec = self.t1a_extractor.extract(
                    (ip_pkt.src, ip_pkt.dst, src_port, dst_port, ip_pkt.proto),
                    pkt_len=pkt_len,
                    now_ns=t0,
                )
                self.sync_model.predict_proba(x_vec)

            # Collector / A2 / A3 / A4: O(1) per-edge-port window counter update (NO ML here!)
            elif self.mode in (
                "collector",
                "A2_Decoupled_Async_WindowML",
                "A3_TwoStage_Gate_Decoupled_TableGuard",
                "A4_Static_Rate_Threshold",
            ) and self._is_edge_port(dpid, in_port):
                key = (dpid, in_port)
                acc = self.port_windows.get(key)
                if acc is None:
                    acc = PortWindowAccumulator()
                    self.port_windows[key] = acc
                acc.record(ip_pkt.src, ip_pkt.dst, src_port, int(ip_pkt.proto), tcp_flags, pkt_len)

                cur_cnt = self.port_burst_count_current.get(key, 0) + 1
                self.port_burst_count_current[key] = cur_cnt
                burst_thresh_pkts = max(3, int(self.gate_pps * self.window_interval_s))
                if cur_cnt >= burst_thresh_pkts and key not in self.port_first_burst_ns:
                    self.port_first_burst_ns[key] = t0

                # A3 Selective Flow-Table Guard: while a port bursts above gate_pps and has NOT
                # been cleared as a legitimate flash crowd by Stage 2, withhold installing 15s
                # 5-tuple rules into Table 0 (forward via PacketOut safely -> 0 table pollution
                # and 0 premature drops!).
                if self.mode == "A3_TwoStage_Gate_Decoupled_TableGuard":
                    in_burst = (
                        cur_cnt >= burst_thresh_pkts
                        or self.port_recent_rate_pps.get(key, 0.0) >= self.gate_pps
                    )
                    if in_burst and time.monotonic() >= self.port_cleared_benign_until.get(key, 0.0):
                        suppress_flow_mod = True
                        self.table_guard_bypassed_flowmods += 1

        if out_port != ofproto.OFPP_FLOOD and not suppress_flow_mod:
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

        self.total_handler_ms.append((time.perf_counter_ns() - t0) / 1_000_000.0)
        self.packet_in_total += 1
