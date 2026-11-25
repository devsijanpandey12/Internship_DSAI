"""Instrumented baseline os-ken OpenFlow 1.3 controller (no AI inference).

Measures Packet-In handling latency distributions, eventlet cooperative event-loop lag,
Flow-Mod installation counts, and OpenFlow OFPErrorMsg table-full refusals.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import eventlet
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import ethernet, ether_types, ipv4, packet, tcp, udp
from os_ken.ofproto import ofproto_v1_3

from evaluation.metrics import summarize_distribution


class BaselineInstrumentedSwitch13(app_manager.OSKenApp):
    """Reactive OpenFlow 1.3 switch with low-overhead in-memory telemetry."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.telemetry_port = int(os.environ.get("SDN_TELEMETRY_PORT", "18080"))
        self.match_mode = os.environ.get("SDN_MATCH_MODE", "5tuple")
        self.flow_idle_timeout = int(os.environ.get("SDN_FLOW_IDLE_TIMEOUT", "15"))
        self.flow_hard_timeout = int(os.environ.get("SDN_FLOW_HARD_TIMEOUT", "30"))
        self.heartbeat_interval_s = float(os.environ.get("SDN_HEARTBEAT_INTERVAL_MS", "50")) / 1000.0

        self.mac_to_port: dict[int, dict[str, int]] = {}
        self.datapaths: dict[int, Any] = {}

        # Per-phase in-memory telemetry (never flushed to disk on the Packet-In hot path)
        self.phase_name = "init"
        self.phase_start_mono_s = time.monotonic()
        self.packet_in_latencies_ms: list[float] = []
        self.event_loop_lag_ms: list[float] = []
        self.packet_in_total = 0
        self.packet_in_by_dpid: dict[int, int] = {}
        self.flow_mod_total = 0
        self.packet_out_total = 0
        self.table_full_errors = 0
        self.other_ofp_errors = 0

        self._heartbeat_thread = hub.spawn(self._heartbeat_loop)
        self._rpc_thread = hub.spawn(self._telemetry_rpc_server)
        self.logger.info(
            "BaselineInstrumentedSwitch13 initialized (match_mode=%s, idle=%ds, hard=%ds, rpc_port=%d)",
            self.match_mode,
            self.flow_idle_timeout,
            self.flow_hard_timeout,
            self.telemetry_port,
        )

    def _reset_phase(self, phase_name: str) -> None:
        self.phase_name = phase_name
        self.phase_start_mono_s = time.monotonic()
        self.packet_in_latencies_ms = []
        self.event_loop_lag_ms = []
        self.packet_in_total = 0
        self.packet_in_by_dpid = {dpid: 0 for dpid in self.datapaths}
        self.flow_mod_total = 0
        self.packet_out_total = 0
        self.table_full_errors = 0
        self.other_ofp_errors = 0

    def _snapshot_phase(self, include_raw: bool = False) -> dict[str, Any]:
        elapsed_s = max(time.monotonic() - self.phase_start_mono_s, 1e-9)
        data: dict[str, Any] = {
            "phase_name": self.phase_name,
            "elapsed_s": elapsed_s,
            "connected_dpids": sorted(self.datapaths.keys()),
            "packet_in_total": self.packet_in_total,
            "packet_in_rate_pps": self.packet_in_total / elapsed_s,
            "packet_in_by_dpid": {str(k): v for k, v in sorted(self.packet_in_by_dpid.items())},
            "flow_mod_total": self.flow_mod_total,
            "packet_out_total": self.packet_out_total,
            "table_full_errors": self.table_full_errors,
            "other_ofp_errors": self.other_ofp_errors,
            "packet_in_handler_ms": summarize_distribution(self.packet_in_latencies_ms),
            "event_loop_lag_ms": summarize_distribution(self.event_loop_lag_ms),
        }
        if include_raw:
            data["raw_packet_in_handler_ms"] = list(self.packet_in_latencies_ms)
            data["raw_event_loop_lag_ms"] = list(self.event_loop_lag_ms)
        return data

    def _heartbeat_loop(self) -> None:
        """Measure cooperative eventlet loop scheduling lag."""
        expected = self.heartbeat_interval_s
        while True:
            t0 = time.perf_counter()
            hub.sleep(expected)
            actual = time.perf_counter() - t0
            lag_ms = max(0.0, (actual - expected) * 1000.0)
            self.event_loop_lag_ms.append(lag_ms)

    def _telemetry_rpc_server(self) -> None:
        """Minimal line-delimited JSON RPC endpoint over loopback."""
        server = eventlet.listen(("127.0.0.1", self.telemetry_port))
        self.logger.info("Telemetry RPC listening on 127.0.0.1:%d", self.telemetry_port)
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
                elif cmd == "reset_phase":
                    self._reset_phase(str(req.get("phase_name", "unnamed")))
                    resp = {"ok": True, "phase_name": self.phase_name}
                elif cmd == "snapshot_phase":
                    resp = {
                        "ok": True,
                        "snapshot": self._snapshot_phase(include_raw=bool(req.get("include_raw", False))),
                    }
                elif cmd == "reinstall_table_miss":
                    for dp in self.datapaths.values():
                        self._install_table_miss(dp)
                    resp = {"ok": True, "dpids": sorted(self.datapaths.keys())}
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
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev: Any) -> None:
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})
        self.packet_in_by_dpid.setdefault(datapath.id, 0)
        self._install_table_miss(datapath)
        self.logger.info("Switch connected: dpid=%s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def error_msg_handler(self, ev: Any) -> None:
        msg = ev.msg
        if (
            msg.type == ofproto_v1_3.OFPET_FLOW_MOD_FAILED
            and msg.code == ofproto_v1_3.OFPFMFC_TABLE_FULL
        ):
            self.table_full_errors += 1
        else:
            self.other_ofp_errors += 1

    def _add_flow(
        self,
        datapath: Any,
        priority: int,
        match: Any,
        actions: list[Any],
        buffer_id: int | None = None,
    ) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs: dict[str, Any] = {
            "datapath": datapath,
            "priority": priority,
            "match": match,
            "instructions": inst,
            "idle_timeout": self.flow_idle_timeout,
            "hard_timeout": self.flow_hard_timeout,
        }
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs["buffer_id"] = buffer_id
        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)
        self.flow_mod_total += 1

    def _build_match(self, parser: Any, in_port: int, pkt: packet.Packet, eth: ethernet.ethernet) -> Any:
        if self.match_mode == "5tuple" and eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt is not None:
                if ip_pkt.proto == 6:
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    if tcp_pkt is not None:
                        return parser.OFPMatch(
                            in_port=in_port,
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=ip_pkt.src,
                            ipv4_dst=ip_pkt.dst,
                            ip_proto=6,
                            tcp_src=tcp_pkt.src_port,
                            tcp_dst=tcp_pkt.dst_port,
                        )
                elif ip_pkt.proto == 17:
                    udp_pkt = pkt.get_protocol(udp.udp)
                    if udp_pkt is not None:
                        return parser.OFPMatch(
                            in_port=in_port,
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=ip_pkt.src,
                            ipv4_dst=ip_pkt.dst,
                            ip_proto=17,
                            udp_src=udp_pkt.src_port,
                            udp_dst=udp_pkt.dst_port,
                        )
                return parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst,
                    ip_proto=ip_pkt.proto,
                )
        return parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)

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

        if out_port != ofproto.OFPP_FLOOD:
            match = self._build_match(parser, in_port, pkt, eth)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._add_flow(datapath, priority=10, match=match, actions=actions, buffer_id=msg.buffer_id)
                self._record_packet_in(dpid, t0)
                return
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
        self.packet_out_total += 1
        self._record_packet_in(dpid, t0)

    def _record_packet_in(self, dpid: int, t0_ns: int) -> None:
        dt_ms = (time.perf_counter_ns() - t0_ns) / 1_000_000.0
        self.packet_in_latencies_ms.append(dt_ms)
        self.packet_in_total += 1
        self.packet_in_by_dpid[dpid] = self.packet_in_by_dpid.get(dpid, 0) + 1
