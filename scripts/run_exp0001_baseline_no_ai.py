"""Automated runner for EXP-0001: Baseline A (SDN without AI).

Starts an isolated os-ken OpenFlow 1.3 controller and minimal 2-switch Mininet topology,
verifies connectivity, sweeps spoofed table-miss Packet-In rates while concurrently
measuring legitimate user QoS and separate controller / OVS / generator resource usage,
and saves immutable experiment manifests, results, and logs.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import psutil
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from evaluation.metrics import (  # noqa: E402
    append_registry_row,
    collect_environment_metadata,
    ensure_non_overwrite,
    get_git_commit,
    sha256_file,
    summarize_distribution,
    write_manifest,
)
from topology.minimal_topology import (  # noqa: E402
    HOST_SPECS,
    build_minimal_network,
    flush_dynamic_flows,
    get_dynamic_flow_count,
)


def rpc_call(host: str, port: int, payload: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with sock.makefile("rw", encoding="utf-8") as stream:
            stream.write(json.dumps(payload) + "\n")
            stream.flush()
            resp_line = stream.readline()
            return json.loads(resp_line)


def wait_for_controller(host: str, port: int, expected_dpids: list[int], timeout_s: float = 20.0) -> int:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = rpc_call(host, port, {"cmd": "ping"}, timeout=1.0)
            if resp.get("ok"):
                dpids = resp.get("connected_dpids", [])
                if all(d in dpids for d in expected_dpids):
                    return int(resp["pid"])
        except Exception:
            pass
        time.sleep(0.25)
    raise TimeoutError(f"Controller at {host}:{port} did not connect dpids {expected_dpids} within {timeout_s}s")


def find_pid_by_name(name: str) -> int | None:
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"] == name:
                return int(proc.info["pid"])
        except Exception:
            continue
    return None


def parse_ping_output(text: str) -> dict[str, Any]:
    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", text)
    loss_pct = float(loss_match.group(1)) if loss_match else 100.0
    rtts = [float(m.group(1)) for m in re.finditer(r"time=(\d+(?:\.\d+)?)\s*ms", text)]
    stats = summarize_distribution(rtts)
    return {
        "loss_pct": loss_pct,
        "rtt_ms": stats,
    }


def parse_iperf3_json(text: str, protocol: str = "udp") -> dict[str, Any]:
    try:
        data = json.loads(text)
        end = data.get("end", {})
        if protocol == "udp":
            sum_recv = end.get("sum_received") or end.get("sum") or {}
            bps = sum_recv.get("bits_per_second") or 0.0
            return {
                "ok": "error" not in data,
                "protocol": "udp",
                "goodput_mbps": float(bps) / 1_000_000.0,
                "jitter_ms": float(sum_recv.get("jitter_ms") or 0.0),
                "lost_percent": float(sum_recv.get("lost_percent") or 0.0),
                "retransmits": 0,
                "error": data.get("error"),
            }
        sum_sent = end.get("sum_sent", {})
        sum_recv = end.get("sum_received", {})
        bps = sum_recv.get("bits_per_second") or sum_sent.get("bits_per_second") or 0.0
        retransmits = sum_sent.get("retransmits", 0)
        return {
            "ok": "error" not in data,
            "protocol": "tcp",
            "goodput_mbps": float(bps) / 1_000_000.0,
            "jitter_ms": None,
            "lost_percent": None,
            "retransmits": int(retransmits) if retransmits is not None else 0,
            "error": data.get("error"),
        }
    except Exception as exc:
        return {
            "ok": False,
            "protocol": protocol,
            "goodput_mbps": 0.0,
            "jitter_ms": None,
            "lost_percent": None,
            "retransmits": -1,
            "error": f"parse_error: {exc}",
        }


def sample_resources_worker(
    stop_event: threading.Event,
    interval_s: float,
    controller_pid: int,
    ovs_pid: int | None,
    gen_pid_getter: Any,
    openflow_version: str,
    records: list[dict[str, Any]],
) -> None:
    ctrl_proc = psutil.Process(controller_pid)
    ovs_proc = psutil.Process(ovs_pid) if ovs_pid else None
    # Prime CPU percentage counters
    ctrl_proc.cpu_percent(interval=None)
    if ovs_proc:
        ovs_proc.cpu_percent(interval=None)

    gen_proc_cache: dict[int, psutil.Process] = {}

    while not stop_event.is_set():
        time.sleep(interval_s)
        sample: dict[str, Any] = {"t_mono": time.monotonic()}
        try:
            sample["controller_cpu_pct"] = ctrl_proc.cpu_percent(interval=None)
            sample["controller_rss_mb"] = ctrl_proc.memory_info().rss / (1024 * 1024)
        except Exception:
            sample["controller_cpu_pct"] = None
            sample["controller_rss_mb"] = None

        if ovs_proc:
            try:
                sample["ovs_cpu_pct"] = ovs_proc.cpu_percent(interval=None)
                sample["ovs_rss_mb"] = ovs_proc.memory_info().rss / (1024 * 1024)
            except Exception:
                sample["ovs_cpu_pct"] = None
                sample["ovs_rss_mb"] = None
        else:
            sample["ovs_cpu_pct"] = None
            sample["ovs_rss_mb"] = None

        gpid = gen_pid_getter()
        if gpid:
            try:
                if gpid not in gen_proc_cache:
                    gen_proc_cache[gpid] = psutil.Process(gpid)
                    gen_proc_cache[gpid].cpu_percent(interval=None)
                    sample["generator_cpu_pct"] = 0.0
                else:
                    sample["generator_cpu_pct"] = gen_proc_cache[gpid].cpu_percent(interval=None)
            except Exception:
                sample["generator_cpu_pct"] = None
        else:
            sample["generator_cpu_pct"] = 0.0

        sample["s1_flows"] = get_dynamic_flow_count("s1", openflow_version)
        sample["s2_flows"] = get_dynamic_flow_count("s2", openflow_version)
        records.append(sample)


def run_experiment(config_path: Path) -> None:
    with config_path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    exp_id = str(cfg["experiment_id"])
    manifest_path = REPO_ROOT / "experiments" / "manifests" / f"{exp_id}.json"
    results_dir = REPO_ROOT / "experiments" / "results" / exp_id
    logs_dir = REPO_ROOT / "experiments" / "logs" / exp_id
    ensure_non_overwrite([manifest_path, results_dir, logs_dir])

    results_dir.mkdir(parents=True, exist_ok=False)
    logs_dir.mkdir(parents=True, exist_ok=False)

    env_meta = collect_environment_metadata()
    git_meta = get_git_commit(REPO_ROOT)

    ctrl_cfg = cfg["controller"]
    topo_cfg = cfg["topology"]
    benign_cfg = cfg["benign_traffic"]
    sweep_cfg = cfg["load_sweep"]
    tel_cfg = cfg["telemetry"]

    controller_log_path = logs_dir / "controller.log"
    controller_env = os.environ.copy()
    controller_env["PYTHONPATH"] = f"{REPO_ROOT / 'src'}:{controller_env.get('PYTHONPATH', '')}"
    controller_env["SDN_TELEMETRY_PORT"] = str(ctrl_cfg["telemetry_port"])
    controller_env["SDN_MATCH_MODE"] = str(ctrl_cfg["match_mode"])
    controller_env["SDN_FLOW_IDLE_TIMEOUT"] = str(topo_cfg["flow_idle_timeout_s"])
    controller_env["SDN_FLOW_HARD_TIMEOUT"] = str(topo_cfg["flow_hard_timeout_s"])
    controller_env["SDN_HEARTBEAT_INTERVAL_MS"] = str(ctrl_cfg["heartbeat_interval_ms"])

    controller_log_fh = controller_log_path.open("w", encoding="utf-8")
    controller_proc = subprocess.Popen(
        [
            "osken-manager",
            "--ofp-tcp-listen-port",
            str(ctrl_cfg["ofp_port"]),
            str(REPO_ROOT / "src" / "controller" / "baseline_controller.py"),
        ],
        env=controller_env,
        stdout=controller_log_fh,
        stderr=subprocess.STDOUT,
    )

    net = None
    phase_summaries: list[dict[str, Any]] = []
    phase_details: list[dict[str, Any]] = []
    raw_latencies: dict[str, Any] = {}
    status = "FAILED"
    failure_reason = ""
    connectivity_loss_pct = 100.0
    topo_meta: dict[str, Any] = {}

    try:
        # Give controller a moment to bind ports before switches connect
        time.sleep(2.0)
        net, topo_meta = build_minimal_network(
            controller_ip=ctrl_cfg["host"],
            controller_port=int(ctrl_cfg["ofp_port"]),
            openflow_version=str(topo_cfg["openflow_version"]),
            flow_table_limit=int(topo_cfg["flow_table_limit"]),
            overflow_policy=str(topo_cfg["overflow_policy"]),
        )
        ctrl_pid = wait_for_controller(
            ctrl_cfg["host"],
            int(ctrl_cfg["telemetry_port"]),
            expected_dpids=[1, 2],
            timeout_s=20.0,
        )
        ovs_pid = find_pid_by_name("ovs-vswitchd")
        print(f"[{exp_id}] Controller ready (pid={ctrl_pid}), ovs-vswitchd pid={ovs_pid}, datapath={topo_meta['ovs_datapath']}", flush=True)

        # Pre-test connectivity sanity check
        connectivity_loss_pct = float(net.pingAll(timeout="2"))
        print(f"[{exp_id}] Pre-test pingAll loss: {connectivity_loss_pct:.2f}%", flush=True)
        if connectivity_loss_pct > 0.0:
            raise RuntimeError(f"Pre-test pingAll failed with {connectivity_loss_pct:.2f}% packet loss")

        h_benign = net.get("h_benign")
        h_attacker = net.get("h_attacker")
        h_server = net.get("h_server")

        # Start persistent benign servers on h_server
        iperf_srv = h_server.popen(["iperf3", "-s"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        echo_srv = h_server.popen(
            [
                "python3",
                str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"),
                "echo_server",
                "--port",
                str(benign_cfg["echo_port"]),
            ],
            env=controller_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.5)

        server_ip = HOST_SPECS["h_server"]["ip"].split("/")[0]
        attacker_mac = HOST_SPECS["h_attacker"]["mac"]
        server_mac = HOST_SPECS["h_server"]["mac"]
        attacker_iface = h_attacker.defaultIntf().name
        flow_limit = int(topo_cfg["flow_table_limit"])

        for idx, rate_pps in enumerate(sweep_cfg["rates_pps"]):
            phase_name = f"rate_{int(rate_pps)}pps"
            print(f"\n[{exp_id}] === Phase {idx + 1}/{len(sweep_cfg['rates_pps'])}: {phase_name} ===", flush=True)

            # Reset switch dynamic flows and allow table/CPU cooldown
            flush_dynamic_flows(["s1", "s2"], str(topo_cfg["openflow_version"]))
            rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "reinstall_table_miss"})
            time.sleep(float(sweep_cfg["cooldown_s"]))

            # Reset controller phase metrics
            rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "reset_phase", "phase_name": phase_name})

            duration_s = float(sweep_cfg["duration_s"])
            ping_count = max(5, int(duration_s / float(benign_cfg["ping_interval_s"])))

            # Start background resource monitor
            res_samples: list[dict[str, Any]] = []
            stop_mon = threading.Event()
            gen_proc_holder: dict[str, Any] = {"proc": None}

            mon_thread = threading.Thread(
                target=sample_resources_worker,
                args=(
                    stop_mon,
                    float(tel_cfg["sample_interval_s"]),
                    ctrl_pid,
                    ovs_pid,
                    lambda: gen_proc_holder["proc"].pid if gen_proc_holder["proc"] else None,
                    str(topo_cfg["openflow_version"]),
                    res_samples,
                ),
                daemon=True,
            )
            mon_thread.start()

            # Launch concurrent benign workloads + controlled spoofed Packet-In generator
            iperf_proto = str(benign_cfg.get("iperf3_protocol", "udp")).lower()
            iperf_cmd = [
                "iperf3",
                "-c",
                server_ip,
                "-t",
                str(int(duration_s)),
                "-J",
            ]
            if iperf_proto == "udp":
                iperf_cmd.extend(["-u", "-b", f"{benign_cfg['iperf3_bitrate_mbps']}M"])
            elif benign_cfg.get("iperf3_bitrate_mbps"):
                iperf_cmd.extend(["-b", f"{benign_cfg['iperf3_bitrate_mbps']}M"])
            ping_cmd = [
                "ping",
                "-i",
                str(benign_cfg["ping_interval_s"]),
                "-c",
                str(ping_count),
                "-w",
                str(int(duration_s) + 1),
                "-W",
                "1",
                server_ip,
            ]
            probe_cmd = [
                "python3",
                str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"),
                "new_flow_probe",
                "--dst-ip",
                server_ip,
                "--dst-port",
                str(benign_cfg["echo_port"]),
                "--rate-hz",
                str(benign_cfg["new_flow_probe_hz"]),
                "--duration",
                str(duration_s),
                "--timeout",
                str(benign_cfg["new_flow_timeout_s"]),
            ]

            iperf_p = h_benign.popen(iperf_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            ping_p = h_benign.popen(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            probe_p = h_benign.popen(probe_cmd, env=controller_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if float(rate_pps) > 0:
                gen_cmd = [
                    "python3",
                    str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"),
                    "spoof_udp",
                    "--iface",
                    attacker_iface,
                    "--src-mac",
                    attacker_mac,
                    "--dst-mac",
                    server_mac,
                    "--dst-ip",
                    server_ip,
                    "--dst-port",
                    str(sweep_cfg["dst_port"]),
                    "--rate-pps",
                    str(rate_pps),
                    "--duration",
                    str(duration_s),
                    "--payload-bytes",
                    str(sweep_cfg["payload_bytes"]),
                    "--seed",
                    str(int(cfg["seed"]) + idx),
                ]
                gen_proc_holder["proc"] = h_attacker.popen(
                    gen_cmd, env=controller_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )

            # Collect process outputs cleanly
            iperf_out, iperf_err = iperf_p.communicate(timeout=duration_s + 20)
            ping_out, _ = ping_p.communicate(timeout=duration_s + 20)
            probe_out, probe_err = probe_p.communicate(timeout=duration_s + 20)

            gen_stats: dict[str, Any] = {
                "target_pps": float(rate_pps),
                "sent_packets": 0,
                "achieved_pps": 0.0,
                "pacing_overruns": 0,
            }
            if gen_proc_holder["proc"] is not None:
                gen_out, gen_err = gen_proc_holder["proc"].communicate(timeout=duration_s + 20)
                if gen_out.strip():
                    gen_stats = json.loads(gen_out.strip().splitlines()[-1])
                elif gen_err:
                    gen_stats["error"] = gen_err.strip()

            stop_mon.set()
            mon_thread.join(timeout=3.0)

            snap_resp = rpc_call(
                ctrl_cfg["host"],
                int(ctrl_cfg["telemetry_port"]),
                {"cmd": "snapshot_phase", "include_raw": True},
                timeout=10.0,
            )
            ctrl_snap = snap_resp["snapshot"]

            iperf_stats = parse_iperf3_json(iperf_out, protocol=iperf_proto)
            if not iperf_stats["ok"] and iperf_err:
                iperf_stats["stderr"] = iperf_err.strip()
            ping_stats = parse_ping_output(ping_out)
            probe_stats = json.loads(probe_out.strip().splitlines()[-1]) if probe_out.strip() else {
                "attempts": 0,
                "successes": 0,
                "failures": 0,
                "success_rate_pct": 0.0,
                "setup_latency_ms": summarize_distribution([]),
                "stderr": probe_err.strip(),
            }

            ctrl_cpus = [s["controller_cpu_pct"] for s in res_samples if s["controller_cpu_pct"] is not None]
            ctrl_rss = [s["controller_rss_mb"] for s in res_samples if s["controller_rss_mb"] is not None]
            ovs_cpus = [s["ovs_cpu_pct"] for s in res_samples if s["ovs_cpu_pct"] is not None]
            gen_cpus = [s["generator_cpu_pct"] for s in res_samples if s["generator_cpu_pct"] is not None]
            s1_flows = [s["s1_flows"] for s in res_samples if s["s1_flows"] >= 0]
            s2_flows = [s["s2_flows"] for s in res_samples if s["s2_flows"] >= 0]

            s1_peak = max(s1_flows) if s1_flows else 0
            s2_peak = max(s2_flows) if s2_flows else 0
            s1_occ_pct = 100.0 * s1_peak / flow_limit

            pi_stats = ctrl_snap["packet_in_handler_ms"]
            lag_stats = ctrl_snap["event_loop_lag_ms"]
            probe_lat = probe_stats["setup_latency_ms"]

            summary_row = {
                "phase": phase_name,
                "target_spoof_pps": float(rate_pps),
                "achieved_spoof_pps": round(float(gen_stats.get("achieved_pps", 0.0)), 2),
                "sent_spoof_packets": int(gen_stats.get("sent_packets", 0)),
                "controller_packet_in_total": int(ctrl_snap["packet_in_total"]),
                "controller_packet_in_pps": round(float(ctrl_snap["packet_in_rate_pps"]), 2),
                "s1_packet_in": int(ctrl_snap["packet_in_by_dpid"].get("1", 0)),
                "s2_packet_in": int(ctrl_snap["packet_in_by_dpid"].get("2", 0)),
                "flow_mod_total": int(ctrl_snap["flow_mod_total"]),
                "table_full_errors": int(ctrl_snap["table_full_errors"]),
                "handler_p50_ms": round(pi_stats["p50"], 4) if pi_stats["p50"] is not None else None,
                "handler_p95_ms": round(pi_stats["p95"], 4) if pi_stats["p95"] is not None else None,
                "handler_p99_ms": round(pi_stats["p99"], 4) if pi_stats["p99"] is not None else None,
                "handler_max_ms": round(pi_stats["max"], 4) if pi_stats["max"] is not None else None,
                "event_loop_lag_p50_ms": round(lag_stats["p50"], 3) if lag_stats["p50"] is not None else None,
                "event_loop_lag_p95_ms": round(lag_stats["p95"], 3) if lag_stats["p95"] is not None else None,
                "event_loop_lag_p99_ms": round(lag_stats["p99"], 3) if lag_stats["p99"] is not None else None,
                "event_loop_lag_max_ms": round(lag_stats["max"], 3) if lag_stats["max"] is not None else None,
                "controller_cpu_mean_pct": round(sum(ctrl_cpus) / len(ctrl_cpus), 2) if ctrl_cpus else None,
                "controller_cpu_peak_pct": round(max(ctrl_cpus), 2) if ctrl_cpus else None,
                "controller_rss_peak_mb": round(max(ctrl_rss), 2) if ctrl_rss else None,
                "ovs_cpu_mean_pct": round(sum(ovs_cpus) / len(ovs_cpus), 2) if ovs_cpus else None,
                "ovs_cpu_peak_pct": round(max(ovs_cpus), 2) if ovs_cpus else None,
                "generator_cpu_mean_pct": round(sum(gen_cpus) / len(gen_cpus), 2) if gen_cpus else None,
                "s1_flows_peak": s1_peak,
                "s2_flows_peak": s2_peak,
                "s1_flow_table_occupancy_pct": round(s1_occ_pct, 2),
                "benign_iperf_mbps": round(float(iperf_stats["goodput_mbps"]), 2),
                "benign_iperf_loss_pct": round(float(iperf_stats["lost_percent"]), 3) if iperf_stats.get("lost_percent") is not None else None,
                "benign_iperf_jitter_ms": round(float(iperf_stats["jitter_ms"]), 3) if iperf_stats.get("jitter_ms") is not None else None,
                "benign_iperf_retransmits": int(iperf_stats["retransmits"]),
                "benign_ping_loss_pct": round(float(ping_stats["loss_pct"]), 2),
                "benign_ping_p50_ms": round(ping_stats["rtt_ms"]["p50"], 3) if ping_stats["rtt_ms"]["p50"] is not None else None,
                "benign_ping_p95_ms": round(ping_stats["rtt_ms"]["p95"], 3) if ping_stats["rtt_ms"]["p95"] is not None else None,
                "benign_new_flow_success_pct": round(float(probe_stats["success_rate_pct"]), 2),
                "benign_new_flow_p50_ms": round(probe_lat["p50"], 3) if probe_lat["p50"] is not None else None,
                "benign_new_flow_p95_ms": round(probe_lat["p95"], 3) if probe_lat["p95"] is not None else None,
            }
            phase_summaries.append(summary_row)

            raw_latencies[phase_name] = {
                "packet_in_handler_ms": ctrl_snap.pop("raw_packet_in_handler_ms", []),
                "event_loop_lag_ms": ctrl_snap.pop("raw_event_loop_lag_ms", []),
                "benign_new_flow_setup_ms": probe_stats.pop("raw_setup_latency_ms", []),
            }
            phase_details.append(
                {
                    "summary": summary_row,
                    "controller_snapshot": ctrl_snap,
                    "generator": gen_stats,
                    "benign_iperf": iperf_stats,
                    "benign_ping": ping_stats,
                    "benign_new_flow_probe": probe_stats,
                    "resource_samples": res_samples,
                }
            )

            print(
                f"  -> sent={summary_row['achieved_spoof_pps']} pps | ctrl_pi={summary_row['controller_packet_in_pps']} pps | "
                f"handler p50/p95/p99={summary_row['handler_p50_ms']}/{summary_row['handler_p95_ms']}/{summary_row['handler_p99_ms']} ms | "
                f"loop_lag p95={summary_row['event_loop_lag_p95_ms']} ms | "
                f"ctrl_cpu={summary_row['controller_cpu_mean_pct']}% | ovs_cpu={summary_row['ovs_cpu_mean_pct']}% | "
                f"s1_occ={summary_row['s1_flow_table_occupancy_pct']}% (full_err={summary_row['table_full_errors']}) | "
                f"iperf={summary_row['benign_iperf_mbps']} Mbps | new_flow_ok={summary_row['benign_new_flow_success_pct']}% (p95={summary_row['benign_new_flow_p95_ms']} ms)",
                flush=True,
            )

        for proc in (iperf_srv, echo_srv):
            try:
                proc.terminate()
            except Exception:
                pass
        status = "SUCCESS"

    except Exception as exc:
        failure_reason = f"{type(exc).__name__}: {exc}"
        print(f"[{exp_id}] FAILED: {failure_reason}", file=sys.stderr, flush=True)
    finally:
        if net is not None:
            try:
                net.stop()
            except Exception:
                pass
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            controller_proc.terminate()
            controller_proc.wait(timeout=5)
        except Exception:
            controller_proc.kill()
        controller_log_fh.close()

    # Persist structured results (always, even on failure)
    summary_csv_path = results_dir / "phase_summary.csv"
    if phase_summaries:
        with summary_csv_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(phase_summaries[0].keys()))
            writer.writeheader()
            writer.writerows(phase_summaries)

    with (results_dir / "phase_details.json").open("w", encoding="utf-8") as f:
        json.dump(phase_details, f, indent=2)
    with (results_dir / "raw_latencies.json").open("w", encoding="utf-8") as f:
        json.dump(raw_latencies, f)

    primary_summary = "FAILED"
    if phase_summaries:
        p0 = phase_summaries[0]
        pmax = phase_summaries[-1]
        primary_summary = (
            f"0pps->max({pmax['target_spoof_pps']:.0f}pps): "
            f"ctrl_pi={p0['controller_packet_in_pps']}->{pmax['controller_packet_in_pps']}pps, "
            f"handler_p99={p0['handler_p99_ms']}->{pmax['handler_p99_ms']}ms, "
            f"loop_lag_p95={p0['event_loop_lag_p95_ms']}->{pmax['event_loop_lag_p95_ms']}ms, "
            f"ctrl_cpu={p0['controller_cpu_mean_pct']}->{pmax['controller_cpu_mean_pct']}%, "
            f"ovs_cpu={p0['ovs_cpu_mean_pct']}->{pmax['ovs_cpu_mean_pct']}%, "
            f"s1_occ={p0['s1_flow_table_occupancy_pct']}->{pmax['s1_flow_table_occupancy_pct']}%"
        )

    manifest = {
        "experiment_id": exp_id,
        "timestamp_utc": env_meta["timestamp_utc"],
        "status": status,
        "failure_reason": failure_reason,
        "phase": cfg["phase"],
        "hypothesis_id": cfg["hypothesis_id"],
        "objective": cfg["objective"].strip(),
        "git": git_meta,
        "config_path": str(config_path.relative_to(REPO_ROOT)),
        "config_sha256": sha256_file(config_path),
        "config": cfg,
        "dataset": {"name": "none_synthetic_live_baseline", "version": "n/a", "sha256": "n/a"},
        "model": {"name": "none_baseline_no_ai"},
        "features": {"mode": "none_openflow_5tuple_l2_forwarding"},
        "topology_runtime": topo_meta,
        "environment": env_meta,
        "pre_test_connectivity_loss_pct": connectivity_loss_pct,
        "metrics_collected": list(phase_summaries[0].keys()) if phase_summaries else [],
        "result_summary": primary_summary,
        "limitations": [
            "Software OVS flow_limit occupancy is a TCAM capacity proxy, not physical hardware TCAM.",
            f"OVS datapath mode: {topo_meta.get('ovs_datapath', 'unknown')} (netdev userspace when WSL2 lacks openvswitch.ko).",
            "Stock WSL2 kernel disables sch_htb/sch_netem; standard veth links used with userspace iperf3 pacing.",
        ],
    }
    write_manifest(manifest_path, manifest)

    append_registry_row(
        REPO_ROOT / "experiments" / "registry.csv",
        {
            "experiment_id": exp_id,
            "timestamp_utc": env_meta["timestamp_utc"],
            "git_commit": git_meta["commit"],
            "phase": cfg["phase"],
            "status": status,
            "hypothesis_id": cfg["hypothesis_id"],
            "objective": cfg["objective"].strip(),
            "environment_mode": f"docker_ubuntu2204_ovs_{topo_meta.get('ovs_datapath', 'unknown')}",
            "primary_metric_summary": primary_summary,
            "manifest_path": str(manifest_path.relative_to(REPO_ROOT)),
            "results_path": str(results_dir.relative_to(REPO_ROOT)),
            "notes": failure_reason if failure_reason else "Pre-test pingAll=0% loss; completed all load phases.",
        },
    )

    if status != "SUCCESS":
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run EXP-0001 Baseline A (No-AI SDN Controller Overhead)")
    parser.add_argument(
        "--config",
        type=Path,
        default=REPO_ROOT / "configs" / "exp0001_baseline_no_ai.yaml",
    )
    args = parser.parse_args()
    run_experiment(args.config.resolve())


if __name__ == "__main__":
    main()
