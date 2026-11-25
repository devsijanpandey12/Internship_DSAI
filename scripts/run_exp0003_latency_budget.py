"""Automated runner for EXP-0003: Core-Pinned Synchronous Compute-Budget Calibration.

Pins os-ken (Core 0), spoof generator (Core 1), and ovs-vswitchd (Cores 2-7) via taskset,
holds spoofed table-miss load fixed at 250 pps (~500 Packet-In/s across s1+s2), and sweeps
calibrated synchronous per-Packet-In CPU work [0.0, 0.25, 0.5, 1.0, 2.0, 4.0] ms across
N repeated seeds, computing mean +/- 95% CI across trials.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import numpy as np
import yaml

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
from topology.minimal_topology import (  # noqa: E402
    HOST_SPECS,
    build_minimal_network,
    flush_dynamic_flows,
)


def pin_pid(pid: int | None, cores: str) -> bool:
    """Apply CPU affinity pinning via taskset; returns True on success."""
    if pid is None:
        return False
    res = subprocess.run(
        ["taskset", "-apc", cores, str(pid)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return res.returncode == 0


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
    cal_cfg = cfg["calibration_sweep"]
    tel_cfg = cfg["telemetry"]
    pin_cfg = cfg.get("cpu_pinning", {})
    seeds = [int(s) for s in cfg["seeds"]]

    controller_log_path = logs_dir / "controller.log"
    controller_env = os.environ.copy()
    controller_env["PYTHONPATH"] = f"{REPO_ROOT / 'src'}:{controller_env.get('PYTHONPATH', '')}"
    controller_env["SDN_TELEMETRY_PORT"] = str(ctrl_cfg["telemetry_port"])
    controller_env["SDN_MATCH_MODE"] = str(ctrl_cfg["match_mode"])
    controller_env["SDN_FLOW_IDLE_TIMEOUT"] = str(topo_cfg["flow_idle_timeout_s"])
    controller_env["SDN_FLOW_HARD_TIMEOUT"] = str(topo_cfg["flow_hard_timeout_s"])
    controller_env["SDN_HEARTBEAT_INTERVAL_MS"] = str(ctrl_cfg["heartbeat_interval_ms"])

    ctrl_cmd = [
        "osken-manager",
        "--ofp-tcp-listen-port",
        str(ctrl_cfg["ofp_port"]),
        str(REPO_ROOT / "src" / "controller" / "baseline_controller.py"),
    ]
    if pin_cfg.get("enabled"):
        ctrl_cmd = ["taskset", "-c", str(pin_cfg["controller_cores"]), *ctrl_cmd]

    controller_log_fh = controller_log_path.open("w", encoding="utf-8")
    controller_proc = subprocess.Popen(
        ctrl_cmd,
        env=controller_env,
        stdout=controller_log_fh,
        stderr=subprocess.STDOUT,
    )

    net = None
    trial_rows: list[dict[str, Any]] = []
    agg_rows: list[dict[str, Any]] = []
    status = "FAILED"
    failure_reason = ""
    connectivity_loss_pct = 100.0
    topo_meta: dict[str, Any] = {}
    pinning_applied: dict[str, Any] = {}

    try:
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
        if pin_cfg.get("enabled"):
            pinning_applied["controller"] = pin_pid(ctrl_pid, str(pin_cfg["controller_cores"]))
            pinning_applied["ovs_vswitchd"] = pin_pid(ovs_pid, str(pin_cfg["ovs_cores"]))
        print(
            f"[{exp_id}] Ready: ctrl_pid={ctrl_pid}, ovs_pid={ovs_pid}, pinning={pinning_applied}",
            flush=True,
        )

        connectivity_loss_pct = float(net.pingAll(timeout="2"))
        if connectivity_loss_pct > 0.0:
            raise RuntimeError(f"Pre-test pingAll failed with {connectivity_loss_pct:.2f}% loss")

        h_benign = net.get("h_benign")
        h_attacker = net.get("h_attacker")
        h_server = net.get("h_server")

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
        fixed_pps = float(cal_cfg["fixed_spoof_pps"])
        duration_s = float(cal_cfg["duration_s"])
        cooldown_s = float(cal_cfg["cooldown_s"])
        levels = [float(x) for x in cal_cfg["inject_cpu_ms_levels"]]

        total_runs = len(seeds) * len(levels)
        run_idx = 0

        for seed in seeds:
            for level_idx, inject_ms in enumerate(levels):
                run_idx += 1
                trial_seed = seed * 100 + level_idx
                phase_name = f"seed{seed}_cpu{inject_ms:.2f}ms"
                print(f"[{exp_id}] ({run_idx}/{total_runs}) {phase_name} @ {fixed_pps:.0f} pps (trial_seed={trial_seed}) ...", flush=True)

                # Wait for any saturated backlog from prior trial to drain at 0 ms before flushing flows
                rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "set_inject_cpu_ms", "ms": 0.0})
                time.sleep(cooldown_s)
                prev_pi = -1
                for _ in range(10):
                    snap_q = rpc_call(
                        ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]),
                        {"cmd": "snapshot_phase", "include_raw": False}, timeout=10.0,
                    )["snapshot"]
                    cur_pi = int(snap_q["packet_in_total"])
                    if cur_pi == prev_pi:
                        break
                    prev_pi = cur_pi
                    time.sleep(0.3)

                flush_dynamic_flows(["s1", "s2"], str(topo_cfg["openflow_version"]))
                rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "reinstall_table_miss"})
                rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "set_inject_cpu_ms", "ms": inject_ms})
                rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "reset_phase", "phase_name": phase_name})

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

                ping_count = max(5, int(duration_s / float(benign_cfg["ping_interval_s"])))
                iperf_cmd = [
                    "iperf3", "-c", server_ip, "-u", "-b", f"{benign_cfg['iperf3_bitrate_mbps']}M",
                    "-t", str(int(duration_s)), "-J",
                ]
                ping_cmd = [
                    "ping", "-i", str(benign_cfg["ping_interval_s"]), "-c", str(ping_count),
                    "-w", str(int(duration_s) + 1), "-W", "1", server_ip,
                ]
                probe_cmd = [
                    "python3", str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"), "new_flow_probe",
                    "--dst-ip", server_ip, "--dst-port", str(benign_cfg["echo_port"]),
                    "--rate-hz", str(benign_cfg["new_flow_probe_hz"]),
                    "--duration", str(duration_s), "--timeout", str(benign_cfg["new_flow_timeout_s"]),
                ]
                gen_cmd = [
                    "python3", str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"), "spoof_udp",
                    "--iface", attacker_iface, "--src-mac", attacker_mac, "--dst-mac", server_mac,
                    "--dst-ip", server_ip, "--dst-port", str(cal_cfg["dst_port"]),
                    "--rate-pps", str(fixed_pps), "--duration", str(duration_s),
                    "--payload-bytes", str(cal_cfg["payload_bytes"]), "--seed", str(trial_seed),
                ]
                if pin_cfg.get("enabled"):
                    gen_cmd = ["taskset", "-c", str(pin_cfg["generator_cores"]), *gen_cmd]

                iperf_p = h_benign.popen(iperf_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                ping_p = h_benign.popen(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                probe_p = h_benign.popen(probe_cmd, env=controller_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                gen_proc_holder["proc"] = h_attacker.popen(gen_cmd, env=controller_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                iperf_out, _ = iperf_p.communicate(timeout=duration_s + 20)
                ping_out, _ = ping_p.communicate(timeout=duration_s + 20)
                probe_out, _ = probe_p.communicate(timeout=duration_s + 20)
                gen_out, _ = gen_proc_holder["proc"].communicate(timeout=duration_s + 20)

                stop_mon.set()
                mon_thread.join(timeout=3.0)

                ctrl_snap = rpc_call(
                    ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]),
                    {"cmd": "snapshot_phase", "include_raw": False}, timeout=20.0,
                )["snapshot"]
                # Reset injected CPU work immediately to drain any residual queue cleanly during cooldown
                rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "set_inject_cpu_ms", "ms": 0.0})

                iperf_stats = parse_iperf3_json(iperf_out, protocol="udp")
                ping_stats = parse_ping_output(ping_out)
                probe_stats = json.loads(probe_out.strip().splitlines()[-1]) if probe_out.strip() else {
                    "success_rate_pct": 0.0, "setup_latency_ms": summarize_distribution([])
                }
                gen_stats = json.loads(gen_out.strip().splitlines()[-1]) if gen_out.strip() else {"achieved_pps": 0.0}

                ctrl_cpus = [s["controller_cpu_pct"] for s in res_samples if s["controller_cpu_pct"] is not None]
                ovs_cpus = [s["ovs_cpu_pct"] for s in res_samples if s["ovs_cpu_pct"] is not None]
                s1_flows = [s["s1_flows"] for s in res_samples if s["s1_flows"] >= 0]
                s1_peak = max(s1_flows) if s1_flows else 0

                pi = ctrl_snap["packet_in_handler_ms"]
                lag = ctrl_snap["event_loop_lag_ms"]
                pl = probe_stats["setup_latency_ms"]

                row = {
                    "seed": seed,
                    "inject_cpu_ms": inject_ms,
                    "achieved_spoof_pps": round(float(gen_stats.get("achieved_pps", 0.0)), 2),
                    "controller_packet_in_pps": round(float(ctrl_snap["packet_in_rate_pps"]), 2),
                    "controller_packet_in_total": int(ctrl_snap["packet_in_total"]),
                    "table_full_errors": int(ctrl_snap["table_full_errors"]),
                    "handler_p50_ms": round(pi["p50"], 4) if pi["p50"] is not None else None,
                    "handler_p95_ms": round(pi["p95"], 4) if pi["p95"] is not None else None,
                    "handler_p99_ms": round(pi["p99"], 4) if pi["p99"] is not None else None,
                    "event_loop_lag_p50_ms": round(lag["p50"], 3) if lag["p50"] is not None else None,
                    "event_loop_lag_p95_ms": round(lag["p95"], 3) if lag["p95"] is not None else None,
                    "event_loop_lag_p99_ms": round(lag["p99"], 3) if lag["p99"] is not None else None,
                    "controller_cpu_mean_pct": round(sum(ctrl_cpus) / len(ctrl_cpus), 2) if ctrl_cpus else None,
                    "controller_cpu_peak_pct": round(max(ctrl_cpus), 2) if ctrl_cpus else None,
                    "ovs_cpu_mean_pct": round(sum(ovs_cpus) / len(ovs_cpus), 2) if ovs_cpus else None,
                    "s1_flow_table_occupancy_pct": round(100.0 * s1_peak / flow_limit, 2),
                    "benign_iperf_mbps": round(float(iperf_stats["goodput_mbps"]), 2),
                    "benign_iperf_loss_pct": round(float(iperf_stats.get("lost_percent") or 0.0), 3),
                    "benign_ping_p95_ms": round(ping_stats["rtt_ms"]["p95"], 3) if ping_stats["rtt_ms"]["p95"] is not None else None,
                    "benign_new_flow_success_pct": round(float(probe_stats["success_rate_pct"]), 2),
                    "benign_new_flow_p50_ms": round(pl["p50"], 3) if pl["p50"] is not None else None,
                    "benign_new_flow_p95_ms": round(pl["p95"], 3) if pl["p95"] is not None else None,
                }
                trial_rows.append(row)
                print(
                    f"  -> pi={row['controller_packet_in_pps']} pps | handler p50/p99={row['handler_p50_ms']}/{row['handler_p99_ms']} ms | "
                    f"lag_p95={row['event_loop_lag_p95_ms']} ms | ctrl_cpu={row['controller_cpu_mean_pct']}% | "
                    f"ovs_cpu={row['ovs_cpu_mean_pct']}% | new_flow_ok={row['benign_new_flow_success_pct']}% (p95={row['benign_new_flow_p95_ms']} ms)",
                    flush=True,
                )

        # Aggregate across seeds per inject_cpu_ms level
        for inject_ms in levels:
            subset = [r for r in trial_rows if r["inject_cpu_ms"] == inject_ms]
            agg: dict[str, Any] = {"inject_cpu_ms": inject_ms, "n_seeds": len(subset)}
            for metric in (
                "controller_packet_in_pps",
                "handler_p50_ms",
                "handler_p99_ms",
                "event_loop_lag_p95_ms",
                "controller_cpu_mean_pct",
                "ovs_cpu_mean_pct",
                "benign_new_flow_success_pct",
                "benign_new_flow_p95_ms",
            ):
                m, s, ci = mean_ci95([r[metric] for r in subset if r[metric] is not None])
                agg[f"{metric}_mean"] = round(m, 3) if m is not None else None
                agg[f"{metric}_ci95"] = round(ci, 3) if ci is not None else None
            agg_rows.append(agg)

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

    primary_summary = "FAILED"
    if agg_rows:
        a0, amax = agg_rows[0], agg_rows[-1]
        primary_summary = (
            f"0ms->4ms (@250pps, N={len(seeds)}): "
            f"ctrl_pi={a0['controller_packet_in_pps_mean']}->{amax['controller_packet_in_pps_mean']}pps, "
            f"ctrl_cpu={a0['controller_cpu_mean_pct_mean']}->{amax['controller_cpu_mean_pct_mean']}%, "
            f"lag_p95={a0['event_loop_lag_p95_ms_mean']}->{amax['event_loop_lag_p95_ms_mean']}ms, "
            f"new_flow_ok={a0['benign_new_flow_success_pct_mean']}->{amax['benign_new_flow_success_pct_mean']}%"
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
        "topology_runtime": topo_meta,
        "environment": env_meta,
        "pre_test_connectivity_loss_pct": connectivity_loss_pct,
        "result_summary": primary_summary,
        "limitations": [
            "Synthetic busy-wait models pure synchronous Python CPU cost without memory/cache footprint of real models (real feature extraction + ML profiled next in Phase 4).",
            "OVS datapath mode: netdev userspace (isolated from controller via taskset core pinning).",
            "Stock WSL2 kernel lacks sch_htb/sch_netem.",
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
            "environment_mode": f"docker_ubuntu2204_ovs_{topo_meta.get('ovs_datapath', 'unknown')}_pinned",
            "primary_metric_summary": primary_summary,
            "manifest_path": str(manifest_path.relative_to(REPO_ROOT)),
            "results_path": str(results_dir.relative_to(REPO_ROOT)),
            "notes": failure_reason if failure_reason else f"Completed {len(trial_rows)} core-pinned trials across {len(seeds)} seeds.",
        },
    )

    if status != "SUCCESS":
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run EXP-0003 Core-Pinned Compute-Budget Calibration")
    parser.add_argument("--config", type=Path, default=REPO_ROOT / "configs" / "exp0003_latency_budget.yaml")
    args = parser.parse_args()
    run_experiment(args.config.resolve())


if __name__ == "__main__":
    main()
