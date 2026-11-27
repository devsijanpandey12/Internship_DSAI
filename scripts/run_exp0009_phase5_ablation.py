"""Runner for EXP-0009: Phase 5B Controlled Single-Variable Ablation (A0-A4).

Compares all 5 architectures (A0 NoAI, A1 Sync LightGBM, A2 Decoupled Async WindowML,
A3 Two-Stage Gate + Decoupled + Flow-Table Guard, A4 Static Rate Threshold) across
N=3 core-pinned unseen seeds under BOTH:
  1. High-rate 800 pps spoofed table-miss flood (tests controller survival, flow-table
     protection, and legitimate new-TCP setup QoS).
  2. Legitimate 60 conn/s TCP flash crowd (tests zero false-positive collateral blocking).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import psutil
import yaml
from scipy.stats import mannwhitneyu

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from evaluation.metrics import (  # noqa: E402
    append_registry_row,
    collect_environment_metadata,
    ensure_non_overwrite,
    get_git_commit,
    mean_ci95,
    sha256_file,
    summarize_distribution,
    write_manifest,
)
from scripts.run_exp0001_baseline_no_ai import (  # noqa: E402
    find_pid_by_name,
    parse_iperf3_json,
    parse_ping_output,
    rpc_call,
    sample_resources_worker,
    wait_for_controller,
)
from scripts.run_exp0003_latency_budget import pin_pid  # noqa: E402
from topology.minimal_topology import HOST_SPECS, build_minimal_network, flush_dynamic_flows  # noqa: E402


def sample_worker_cpu_thread(
    stop_event: threading.Event,
    interval_s: float,
    worker_pid_getter: Any,
    out_list: list[float],
) -> None:
    proc_cache: dict[int, psutil.Process] = {}
    while not stop_event.is_set():
        time.sleep(interval_s)
        wpid = worker_pid_getter()
        if not wpid:
            continue
        try:
            if wpid not in proc_cache:
                proc_cache[wpid] = psutil.Process(wpid)
                proc_cache[wpid].cpu_percent(interval=None)
            else:
                out_list.append(proc_cache[wpid].cpu_percent(interval=None))
        except Exception:
            pass


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
    tel_cfg = cfg["telemetry"]
    pin_cfg = cfg.get("cpu_pinning", {})
    seeds = [int(s) for s in cfg["seeds"]]
    scenarios = cfg["scenarios"]
    architectures = [str(a) for a in cfg["architectures"]]

    sync_model_path = str((REPO_ROOT / cfg["models"]["sync_t1a_lgbm_path"]).resolve())
    stage2_model_path = str((REPO_ROOT / cfg["models"]["stage2_window_lgbm_path"]).resolve())
    for mp_check in (sync_model_path, stage2_model_path):
        if not Path(mp_check).exists():
            raise FileNotFoundError(f"Required model artifact missing: {mp_check}")

    controller_env = os.environ.copy()
    controller_env["PYTHONPATH"] = f"{REPO_ROOT / 'src'}:{controller_env.get('PYTHONPATH', '')}"
    controller_env["SDN_TELEMETRY_PORT"] = str(ctrl_cfg["telemetry_port"])
    controller_env["SDN_WINDOW_INTERVAL_MS"] = str(ctrl_cfg["window_interval_ms"])
    controller_env["SDN_FLOW_IDLE_TIMEOUT"] = str(topo_cfg["flow_idle_timeout_s"])
    controller_env["SDN_FLOW_HARD_TIMEOUT"] = str(topo_cfg["flow_hard_timeout_s"])
    controller_env["SDN_HEARTBEAT_INTERVAL_MS"] = str(ctrl_cfg["heartbeat_interval_ms"])
    controller_env["SDN_WORKER_CORE"] = str(pin_cfg.get("worker_core", 8))
    controller_env["OMP_NUM_THREADS"] = "1"
    controller_env["OPENBLAS_NUM_THREADS"] = "1"
    controller_env["MKL_NUM_THREADS"] = "1"

    ctrl_cmd = [
        "osken-manager",
        "--ofp-tcp-listen-port",
        str(ctrl_cfg["ofp_port"]),
        str(REPO_ROOT / "src" / "controller" / "two_stage_controller.py"),
    ]
    if pin_cfg.get("enabled"):
        ctrl_cmd = ["taskset", "-c", str(pin_cfg["controller_cores"]), *ctrl_cmd]

    controller_log_fh = (logs_dir / "controller.log").open("w", encoding="utf-8")
    controller_proc = subprocess.Popen(ctrl_cmd, env=controller_env, stdout=controller_log_fh, stderr=subprocess.STDOUT)

    net = None
    trial_rows: list[dict[str, Any]] = []
    agg_rows: list[dict[str, Any]] = []
    stat_tests: list[dict[str, Any]] = []
    status = "FAILED"
    failure_reason = ""
    topo_meta: dict[str, Any] = {}
    pinning_applied: dict[str, Any] = {}

    try:
        time.sleep(2.5)
        net, topo_meta = build_minimal_network(
            controller_ip=ctrl_cfg["host"],
            controller_port=int(ctrl_cfg["ofp_port"]),
            openflow_version=str(topo_cfg["openflow_version"]),
            flow_table_limit=int(topo_cfg["flow_table_limit"]),
            overflow_policy=str(topo_cfg["overflow_policy"]),
        )
        ctrl_pid = wait_for_controller(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), [1, 2], timeout_s=25.0)
        ovs_pid = find_pid_by_name("ovs-vswitchd")
        if pin_cfg.get("enabled"):
            pinning_applied["controller"] = pin_pid(ctrl_pid, str(pin_cfg["controller_cores"]))
            pinning_applied["ovs_vswitchd"] = pin_pid(ovs_pid, str(pin_cfg["ovs_cores"]))
            pinning_applied["worker_core"] = pin_cfg.get("worker_core", 8)

        loss = float(net.pingAll(timeout="2"))
        if loss > 0.0:
            raise RuntimeError(f"Pre-test pingAll loss={loss}%")

        h_benign = net.get("h_benign")
        h_attacker = net.get("h_attacker")
        h_server = net.get("h_server")
        iperf_srv = h_server.popen(["iperf3", "-s"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        echo_srv = h_server.popen(
            ["python3", str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"), "echo_server", "--port", str(benign_cfg["echo_port"])],
            env=controller_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(0.5)

        server_ip = HOST_SPECS["h_server"]["ip"].split("/")[0]
        attacker_mac = HOST_SPECS["h_attacker"]["mac"]
        server_mac = HOST_SPECS["h_server"]["mac"]
        attacker_iface = h_attacker.defaultIntf().name
        flow_limit = int(topo_cfg["flow_table_limit"])

        total_runs = len(scenarios) * len(seeds) * len(architectures)
        run_idx = 0

        for scen in scenarios:
            sname = str(scen["name"])
            skind = str(scen["kind"])
            dur_s = float(scen["duration_s"])
            cd_s = float(scen["cooldown_s"])

            for seed in seeds:
                for arch_idx, arch in enumerate(architectures):
                    run_idx += 1
                    trial_seed = seed * 100 + arch_idx
                    phase_name = f"{sname}_seed{seed}_{arch}"
                    print(f"[{exp_id}] ({run_idx}/{total_runs}) {phase_name} ...", flush=True)

                    # Drain cleanly in A0 mode before flushing flows (zero carryover!)
                    rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "configure", "mode": "A0_Baseline_NoAI"}, timeout=15.0)
                    time.sleep(cd_s)
                    prev_pi = -1
                    for _ in range(12):
                        sq = rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "snapshot_phase"}, timeout=10.0)["snapshot"]
                        if int(sq["packet_in_total"]) == prev_pi:
                            break
                        prev_pi = int(sq["packet_in_total"])
                        time.sleep(0.3)

                    flush_dynamic_flows(["s1", "s2"], str(topo_cfg["openflow_version"]))
                    rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "reinstall_table_miss"})

                    cfg_resp = rpc_call(
                        ctrl_cfg["host"],
                        int(ctrl_cfg["telemetry_port"]),
                        {
                            "cmd": "configure",
                            "mode": arch,
                            "gate_pps": ctrl_cfg["gate_pps"],
                            "mitigation_hard_timeout_s": ctrl_cfg["mitigation_hard_timeout_s"],
                            "window_interval_ms": ctrl_cfg["window_interval_ms"],
                            "edge_ports": ctrl_cfg["edge_ports"],
                            "sync_model_path": sync_model_path,
                            "stage2_model_path": stage2_model_path,
                        },
                        timeout=25.0,
                    )
                    worker_pid = cfg_resp.get("worker_pid")
                    rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "reset_phase", "phase_name": phase_name})

                    res_samples: list[dict[str, Any]] = []
                    worker_cpus: list[float] = []
                    stop_mon = threading.Event()
                    gen_holder: dict[str, Any] = {"proc": None}

                    mon_t = threading.Thread(
                        target=sample_resources_worker,
                        args=(
                            stop_mon,
                            float(tel_cfg["sample_interval_s"]),
                            ctrl_pid,
                            ovs_pid,
                            lambda: gen_holder["proc"].pid if gen_holder["proc"] else None,
                            str(topo_cfg["openflow_version"]),
                            res_samples,
                        ),
                        daemon=True,
                    )
                    wmon_t = threading.Thread(
                        target=sample_worker_cpu_thread,
                        args=(stop_mon, float(tel_cfg["sample_interval_s"]), lambda: worker_pid, worker_cpus),
                        daemon=True,
                    )
                    mon_t.start()
                    wmon_t.start()

                    ping_count = max(5, int(dur_s / float(benign_cfg["ping_interval_s"])))
                    iperf_p = h_benign.popen(
                        ["iperf3", "-c", server_ip, "-u", "-b", f"{benign_cfg['iperf3_bitrate_mbps']}M", "-t", str(int(dur_s)), "-J"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    )
                    ping_p = h_benign.popen(
                        ["ping", "-i", str(benign_cfg["ping_interval_s"]), "-c", str(ping_count), "-w", str(int(dur_s) + 1), "-W", "1", server_ip],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    )

                    if skind in ("spoof_udp", "spoof_syn"):
                        probe_p = h_benign.popen(
                            [
                                "python3", str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"), "new_flow_probe",
                                "--dst-ip", server_ip, "--dst-port", str(benign_cfg["echo_port"]),
                                "--rate-hz", str(benign_cfg["new_flow_probe_hz"]),
                                "--duration", str(dur_s), "--timeout", str(benign_cfg["new_flow_timeout_s"]),
                            ],
                            env=controller_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                        )
                        if skind == "spoof_udp":
                            gen_cmd = [
                                "python3", str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"), "spoof_udp",
                                "--iface", attacker_iface, "--src-mac", attacker_mac, "--dst-mac", server_mac,
                                "--dst-ip", server_ip, "--dst-port", "9999",
                                "--rate-pps", str(scen["rate_pps"]), "--duration", str(dur_s),
                                "--min-payload-bytes", str(scen["min_payload_bytes"]),
                                "--max-payload-bytes", str(scen["max_payload_bytes"]),
                                "--seed", str(trial_seed),
                            ]
                        else:
                            gen_cmd = [
                                "python3", str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"), "spoof_syn",
                                "--iface", attacker_iface, "--src-mac", attacker_mac, "--dst-mac", server_mac,
                                "--dst-ip", server_ip, "--dst-port", str(benign_cfg["echo_port"]),
                                "--rate-pps", str(scen["rate_pps"]), "--duration", str(dur_s),
                                "--seed", str(trial_seed),
                            ]
                        if pin_cfg.get("enabled"):
                            gen_cmd = ["taskset", "-c", str(pin_cfg["generator_cores"]), *gen_cmd]
                        gen_holder["proc"] = h_attacker.popen(gen_cmd, env=controller_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    else:
                        # Legitimate TCP Flash Crowd on h_benign (s1:p1) — zero attacker traffic!
                        probe_p = h_benign.popen(
                            [
                                "python3", str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"), "flash_crowd",
                                "--dst-ip", server_ip, "--dst-port", str(benign_cfg["echo_port"]),
                                "--rate-hz", str(scen["rate_hz"]), "--duration", str(dur_s),
                                "--concurrency", "32", "--seed", str(trial_seed),
                            ],
                            env=controller_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                        )

                    iperf_timed_out = False
                    try:
                        iperf_out, _ = iperf_p.communicate(timeout=dur_s + 8)
                    except subprocess.TimeoutExpired:
                        iperf_timed_out = True
                        iperf_p.kill()
                        iperf_out, _ = iperf_p.communicate()
                        # Restart iperf3 server cleanly so a half-open socket blocked by A4 never stalls next trial
                        try:
                            iperf_srv.kill()
                            iperf_srv.wait(timeout=2)
                        except Exception:
                            pass
                        iperf_srv = h_server.popen(["iperf3", "-s"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        time.sleep(0.3)
                    try:
                        ping_out, _ = ping_p.communicate(timeout=dur_s + 8)
                    except subprocess.TimeoutExpired:
                        ping_p.kill()
                        ping_out, _ = ping_p.communicate()
                    try:
                        probe_out, _ = probe_p.communicate(timeout=dur_s + 12)
                    except subprocess.TimeoutExpired:
                        probe_p.kill()
                        probe_out, _ = probe_p.communicate()
                    if gen_holder["proc"] is not None:
                        try:
                            gen_holder["proc"].communicate(timeout=dur_s + 10)
                        except subprocess.TimeoutExpired:
                            gen_holder["proc"].kill()
                            gen_holder["proc"].communicate()

                    stop_mon.set()
                    mon_t.join(timeout=3.0)
                    wmon_t.join(timeout=3.0)

                    ctrl_snap = rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "snapshot_phase"}, timeout=25.0)["snapshot"]
                    iperf_stats = (
                        {"ok": False, "goodput_mbps": 0.0, "error": "timeout_control_blocked"}
                        if iperf_timed_out
                        else parse_iperf3_json(iperf_out, protocol="udp")
                    )
                    ping_stats = parse_ping_output(ping_out)
                    probe_stats = json.loads(probe_out.strip().splitlines()[-1]) if probe_out.strip() else {
                        "success_rate_pct": 0.0, "setup_latency_ms": summarize_distribution([])
                    }

                    ctrl_cpus = [s["controller_cpu_pct"] for s in res_samples if s["controller_cpu_pct"] is not None]
                    ovs_cpus = [s["ovs_cpu_pct"] for s in res_samples if s["ovs_cpu_pct"] is not None]
                    s1_flows = [s["s1_flows"] for s in res_samples if s["s1_flows"] >= 0]
                    s1_peak = max(s1_flows) if s1_flows else 0

                    tot = ctrl_snap["total_handler_ms"]
                    lag = ctrl_snap["event_loop_lag_ms"]
                    d2m = ctrl_snap["detection_to_mitigation_ms"]
                    pl = probe_stats["setup_latency_ms"]
                    mit_ports = ctrl_snap.get("mitigations_by_port", {})

                    row = {
                        "scenario": sname,
                        "seed": seed,
                        "architecture": arch,
                        "controller_packet_in_pps": round(float(ctrl_snap["packet_in_rate_pps"]), 2),
                        "controller_packet_in_total": int(ctrl_snap["packet_in_total"]),
                        "handler_p50_ms": round(tot["p50"], 4) if tot["p50"] is not None else None,
                        "handler_p99_ms": round(tot["p99"], 4) if tot["p99"] is not None else None,
                        "event_loop_lag_p95_ms": round(lag["p95"], 3) if lag["p95"] is not None else None,
                        "controller_cpu_mean_pct": round(sum(ctrl_cpus) / len(ctrl_cpus), 2) if ctrl_cpus else None,
                        "worker_cpu_mean_pct": round(sum(worker_cpus) / len(worker_cpus), 2) if worker_cpus else 0.0,
                        "ovs_cpu_mean_pct": round(sum(ovs_cpus) / len(ovs_cpus), 2) if ovs_cpus else None,
                        "s1_flows_peak": s1_peak,
                        "s1_flow_table_occupancy_pct": round(100.0 * s1_peak / flow_limit, 2),
                        "table_full_errors": int(ctrl_snap["table_full_errors"]),
                        "table_guard_bypassed_flowmods": int(ctrl_snap["table_guard_bypassed_flowmods"]),
                        "stage1_gate_triggers": int(ctrl_snap["stage1_gate_triggers"]),
                        "stage2_ipc_submitted": int(ctrl_snap["stage2_ipc_submitted"]),
                        "mitigation_rules_installed": int(ctrl_snap["mitigation_rules_installed"]),
                        "false_mitigations_benign_port": int(mit_ports.get("s1:p1", 0)),
                        "true_mitigations_attack_port": int(mit_ports.get("s1:p2", 0)),
                        "detection_to_mitigation_ms": round(d2m["p50"], 2) if d2m["p50"] is not None else None,
                        "benign_iperf_mbps": round(float(iperf_stats["goodput_mbps"]), 2),
                        "benign_ping_p95_ms": round(ping_stats["rtt_ms"]["p95"], 3) if ping_stats["rtt_ms"]["p95"] is not None else None,
                        "benign_tcp_success_pct": round(float(probe_stats["success_rate_pct"]), 2),
                        "benign_tcp_p95_ms": round(pl["p95"], 3) if pl["p95"] is not None else None,
                    }
                    trial_rows.append(row)
                    print(
                        f"  -> pi={row['controller_packet_in_pps']:6.1f} pps | cpu={row['controller_cpu_mean_pct']:5.1f}% (wkr={row['worker_cpu_mean_pct']:4.1f}%) | "
                        f"lag_p95={row['event_loop_lag_p95_ms']:5.2f} ms | s1_occ={row['s1_flow_table_occupancy_pct']:5.2f}% (full={row['table_full_errors']}) | "
                        f"mit(p1/p2)={row['false_mitigations_benign_port']}/{row['true_mitigations_attack_port']} (d2m={row['detection_to_mitigation_ms']}ms) | "
                        f"tcp_ok={row['benign_tcp_success_pct']:5.1f}% (p95={row['benign_tcp_p95_ms']}ms)",
                        flush=True,
                    )

        # Aggregate per (scenario, architecture) with 95% CI
        for scen in scenarios:
            sname = str(scen["name"])
            for arch in architectures:
                subset = [r for r in trial_rows if r["scenario"] == sname and r["architecture"] == arch]
                agg: dict[str, Any] = {"scenario": sname, "architecture": arch, "n_seeds": len(subset)}
                for metric in (
                    "controller_packet_in_pps",
                    "handler_p50_ms",
                    "handler_p99_ms",
                    "event_loop_lag_p95_ms",
                    "controller_cpu_mean_pct",
                    "worker_cpu_mean_pct",
                    "s1_flow_table_occupancy_pct",
                    "table_full_errors",
                    "stage2_ipc_submitted",
                    "false_mitigations_benign_port",
                    "true_mitigations_attack_port",
                    "detection_to_mitigation_ms",
                    "benign_tcp_success_pct",
                    "benign_tcp_p95_ms",
                ):
                    m, _, ci = mean_ci95([r[metric] for r in subset if r[metric] is not None])
                    agg[f"{metric}_mean"] = round(m, 3) if m is not None else None
                    agg[f"{metric}_ci95"] = round(ci, 3) if ci is not None else None
                agg_rows.append(agg)

        # Pairwise Mann-Whitney U checks across all flood & flash-crowd scenarios
        pairs = []
        for scen in scenarios:
            sn = str(scen["name"])
            if scen["kind"] in ("spoof_udp", "spoof_syn"):
                pairs.extend([
                    (sn, "A3_TwoStage_Gate_Decoupled_TableGuard", "A1_Sync_Light_LGBM", "controller_cpu_mean_pct"),
                    (sn, "A3_TwoStage_Gate_Decoupled_TableGuard", "A1_Sync_Light_LGBM", "benign_tcp_success_pct"),
                    (sn, "A3_TwoStage_Gate_Decoupled_TableGuard", "A1_Sync_Light_LGBM", "event_loop_lag_p95_ms"),
                    (sn, "A3_TwoStage_Gate_Decoupled_TableGuard", "A2_Decoupled_Async_WindowML", "s1_flow_table_occupancy_pct"),
                    (sn, "A3_TwoStage_Gate_Decoupled_TableGuard", "A0_Baseline_NoAI", "controller_cpu_mean_pct"),
                ])
            else:
                pairs.extend([
                    (sn, "A3_TwoStage_Gate_Decoupled_TableGuard", "A4_Static_Rate_Threshold", "benign_tcp_success_pct"),
                    (sn, "A3_TwoStage_Gate_Decoupled_TableGuard", "A4_Static_Rate_Threshold", "false_mitigations_benign_port"),
                ])
        for sname, a_prop, a_base, metric in pairs:
            v1 = [r[metric] for r in trial_rows if r["scenario"] == sname and r["architecture"] == a_prop and r[metric] is not None]
            v2 = [r[metric] for r in trial_rows if r["scenario"] == sname and r["architecture"] == a_base and r[metric] is not None]
            if v1 and v2:
                u_stat, p_val = mannwhitneyu(v1, v2, alternative="two-sided")
                stat_tests.append(
                    {
                        "scenario": sname,
                        "metric": metric,
                        "proposed": a_prop,
                        "baseline": a_base,
                        "proposed_mean": round(sum(v1) / len(v1), 3),
                        "baseline_mean": round(sum(v2) / len(v2), 3),
                        "mann_whitney_u": float(u_stat),
                        "p_value": round(float(p_val), 5),
                    }
                )

        for p in (iperf_srv, echo_srv):
            try:
                p.terminate()
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

    if trial_rows:
        with (results_dir / "trial_results.csv").open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(trial_rows[0].keys()))
            writer.writeheader()
            writer.writerows(trial_rows)
    if agg_rows:
        with (results_dir / "aggregated_summary.csv").open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(agg_rows[0].keys()))
            writer.writeheader()
            writer.writerows(agg_rows)
    with (results_dir / "statistical_tests.json").open("w", encoding="utf-8") as f:
        json.dump(stat_tests, f, indent=2)

    primary_summary = "FAILED"
    if agg_rows:
        idx = {(r["scenario"], r["architecture"]): r for r in agg_rows}
        a1f = idx.get(("spoof_udp_800pps", "A1_Sync_Light_LGBM")) or idx.get(("spoof_flood_800pps", "A1_Sync_Light_LGBM"), {})
        a2f = idx.get(("spoof_udp_800pps", "A2_Decoupled_Async_WindowML")) or idx.get(("spoof_flood_800pps", "A2_Decoupled_Async_WindowML"), {})
        a3f = idx.get(("spoof_udp_800pps", "A3_TwoStage_Gate_Decoupled_TableGuard")) or idx.get(("spoof_flood_800pps", "A3_TwoStage_Gate_Decoupled_TableGuard"), {})
        a3c = idx.get(("benign_flash_crowd_60hz", "A3_TwoStage_Gate_Decoupled_TableGuard"), {})
        a4c = idx.get(("benign_flash_crowd_60hz", "A4_Static_Rate_Threshold"), {})
        primary_summary = (
            f"Flood800: A1_cpu={a1f.get('controller_cpu_mean_pct_mean')}%/ok={a1f.get('benign_tcp_success_pct_mean')}% vs "
            f"A2_occ={a2f.get('s1_flow_table_occupancy_pct_mean')}% vs "
            f"A3_cpu={a3f.get('controller_cpu_mean_pct_mean')}%/occ={a3f.get('s1_flow_table_occupancy_pct_mean')}%/ok={a3f.get('benign_tcp_success_pct_mean')}% | "
            f"Flash60Hz: A4_ok={a4c.get('benign_tcp_success_pct_mean')}% vs A3_ok={a3c.get('benign_tcp_success_pct_mean')}%"
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
        "cpu_pinning_applied": pinning_applied,
        "statistical_tests": stat_tests,
        "topology_runtime": topo_meta,
        "environment": env_meta,
        "result_summary": primary_summary,
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
            "environment_mode": f"docker_ubuntu2204_ovs_{topo_meta.get('ovs_datapath', 'unknown')}_pinned",
            "primary_metric_summary": primary_summary,
            "manifest_path": str(manifest_path.relative_to(REPO_ROOT)),
            "results_path": str(results_dir.relative_to(REPO_ROOT)),
            "notes": failure_reason if failure_reason else f"Completed {len(trial_rows)} Phase 5B ablation trials across 5 architectures x 2 scenarios x {len(seeds)} seeds.",
        },
    )
    if status != "SUCCESS":
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run EXP-0009 Phase 5B Single-Variable Ablation")
    parser.add_argument("--config", type=Path, default=REPO_ROOT / "configs" / "exp0009_phase5_ablation.yaml")
    args = parser.parse_args()
    run_experiment(args.config.resolve())


if __name__ == "__main__":
    main()
