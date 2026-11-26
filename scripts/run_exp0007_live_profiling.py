"""Runner for EXP-0007: Live SDN Component Attribution (Baseline A vs B vs C).

1. Trains container-native InSDN models cleanly inside the exact Linux SDN runtime so
   offline F1/FPR and live inference share identical libraries and zero pickle skew.
2. Sweeps all 8 factorial pipelines (NoAI, FeatsOnly T1a/T3, Baseline B LR/LGBM/XGB,
   Baseline C T1a-RF & T3-RF) across N=3 core-pinned seeds at 250 pps spoofed table-miss load.
3. Logs exact microsecond attribution: base_ofp_ms, feature_extract_ms, model_infer_ms,
   event_loop_lag_ms, controller/OVS CPU, Packet-In throughput, and benign new-flow QoS.
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

import joblib
import numpy as np
import yaml
from sklearn.model_selection import train_test_split

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from data.insdn_loader import load_clean_insdn  # noqa: E402
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
from models.offline_baselines import (  # noqa: E402
    build_model,
    compute_classification_metrics,
    set_single_thread_inference,
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
from topology.minimal_topology import (  # noqa: E402
    HOST_SPECS,
    build_minimal_network,
    flush_dynamic_flows,
)


def train_container_models(
    cfg: dict[str, Any],
    models_dir: Path,
) -> tuple[dict[str, str], dict[str, list[str]], dict[str, dict[str, Any]]]:
    """Train exact leakage-free InSDN models inside Linux SDN container for live deployment."""
    models_dir.mkdir(parents=True, exist_ok=True)
    raw_csv = REPO_ROOT / cfg["dataset"]["raw_csv"]
    seed = int(cfg["dataset"]["train_seed"])

    print(f"[EXP-0007] Training container-native InSDN models from {raw_csv} ...", flush=True)
    X_all, y_bin, y_mc, tiers = load_clean_insdn(
        raw_csv, include_dst_port=False, deduplicate_features=True
    )
    idx_all = np.arange(len(X_all))
    strat_labels = y_mc.to_numpy()
    idx_train, idx_tmp = train_test_split(idx_all, test_size=0.30, random_state=seed, stratify=strat_labels)
    _, idx_test = train_test_split(idx_tmp, test_size=0.50, random_state=seed, stratify=strat_labels[idx_tmp])

    y_tr = y_bin.to_numpy()[idx_train]
    y_te = y_bin.to_numpy()[idx_test]

    model_paths: dict[str, str] = {}
    offline_scores: dict[str, dict[str, Any]] = {}

    needed: list[tuple[str, str]] = []
    for p in cfg["pipelines"]:
        if p.get("model") and p.get("tier"):
            pair = (str(p["tier"]), str(p["model"]))
            if pair not in needed:
                needed.append(pair)

    for tier_name, model_name in needed:
        cols = tiers[tier_name]
        X_tier = X_all[cols].to_numpy(dtype=np.float32)
        t0 = time.perf_counter()
        model = build_model(model_name, seed=seed, n_jobs_train=4)
        model.fit(X_tier[idx_train], y_tr)
        set_single_thread_inference(model)
        fit_s = time.perf_counter() - t0

        probs = model.predict_proba(X_tier[idx_test])[:, 1]
        preds = (probs >= 0.5).astype(int)
        metrics = compute_classification_metrics(y_te, preds, probs)

        out_path = models_dir / f"{tier_name}__{model_name}.joblib"
        joblib.dump({"model": model, "features": cols, "tier": tier_name, "model_name": model_name}, out_path)
        key = f"{tier_name}__{model_name}"
        model_paths[key] = str(out_path)
        offline_scores[key] = {
            "n_features": len(cols),
            "train_time_s": round(fit_s, 2),
            "test_macro_f1": round(metrics["macro_f1"], 5),
            "test_fpr": round(metrics["fpr"], 5),
            "test_pr_auc": round(metrics["pr_auc"], 5) if metrics["pr_auc"] is not None else None,
        }
        print(
            f"  trained {key:<38s} | Test F1={metrics['macro_f1']:.4f} | FPR={metrics['fpr']*100:.2f}% | {fit_s:.1f}s",
            flush=True,
        )

    return model_paths, tiers, offline_scores


def run_experiment(config_path: Path) -> None:
    with config_path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    exp_id = str(cfg["experiment_id"])
    manifest_path = REPO_ROOT / "experiments" / "manifests" / f"{exp_id}.json"
    results_dir = REPO_ROOT / "experiments" / "results" / exp_id
    logs_dir = REPO_ROOT / "experiments" / "logs" / exp_id
    artifacts_dir = REPO_ROOT / "experiments" / "artifacts" / exp_id
    ensure_non_overwrite([manifest_path, results_dir, logs_dir, artifacts_dir])

    results_dir.mkdir(parents=True, exist_ok=False)
    logs_dir.mkdir(parents=True, exist_ok=False)
    artifacts_dir.mkdir(parents=True, exist_ok=False)

    env_meta = collect_environment_metadata()
    git_meta = get_git_commit(REPO_ROOT)
    ds_manifest = json.loads((REPO_ROOT / cfg["dataset"]["manifest_json"]).read_text(encoding="utf-8"))

    # Step 1: Train container-native models (identical Linux runtime as live os-ken)
    model_paths, tiers, offline_scores = train_container_models(cfg, artifacts_dir / "models")

    ctrl_cfg = cfg["controller"]
    topo_cfg = cfg["topology"]
    benign_cfg = cfg["benign_traffic"]
    load_cfg = cfg["load"]
    tel_cfg = cfg["telemetry"]
    pin_cfg = cfg.get("cpu_pinning", {})
    seeds = [int(s) for s in cfg["seeds"]]
    pipelines = cfg["pipelines"]

    controller_log_path = logs_dir / "controller.log"
    controller_env = os.environ.copy()
    controller_env["PYTHONPATH"] = f"{REPO_ROOT / 'src'}:{controller_env.get('PYTHONPATH', '')}"
    controller_env["SDN_TELEMETRY_PORT"] = str(ctrl_cfg["telemetry_port"])
    controller_env["SDN_FLOW_IDLE_TIMEOUT"] = str(topo_cfg["flow_idle_timeout_s"])
    controller_env["SDN_FLOW_HARD_TIMEOUT"] = str(topo_cfg["flow_hard_timeout_s"])
    controller_env["SDN_HEARTBEAT_INTERVAL_MS"] = str(ctrl_cfg["heartbeat_interval_ms"])
    # Ensure OpenMP / BLAS threads inside os-ken stay strictly single-threaded
    controller_env["OMP_NUM_THREADS"] = "1"
    controller_env["OPENBLAS_NUM_THREADS"] = "1"
    controller_env["MKL_NUM_THREADS"] = "1"

    ctrl_cmd = [
        "osken-manager",
        "--ofp-tcp-listen-port",
        str(ctrl_cfg["ofp_port"]),
        str(REPO_ROOT / "src" / "controller" / "ai_profiled_controller.py"),
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
        time.sleep(2.5)
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
            timeout_s=25.0,
        )
        ovs_pid = find_pid_by_name("ovs-vswitchd")
        if pin_cfg.get("enabled"):
            pinning_applied["controller"] = pin_pid(ctrl_pid, str(pin_cfg["controller_cores"]))
            pinning_applied["ovs_vswitchd"] = pin_pid(ovs_pid, str(pin_cfg["ovs_cores"]))
        print(f"\n[{exp_id}] Live testbed ready: ctrl_pid={ctrl_pid}, ovs_pid={ovs_pid}, pinning={pinning_applied}", flush=True)

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
        fixed_pps = float(load_cfg["fixed_spoof_pps"])
        duration_s = float(load_cfg["duration_s"])
        cooldown_s = float(load_cfg["cooldown_s"])

        total_runs = len(seeds) * len(pipelines)
        run_idx = 0

        for seed in seeds:
            for pipe_idx, pipe in enumerate(pipelines):
                run_idx += 1
                pname = str(pipe["name"])
                trial_seed = seed * 100 + pipe_idx
                phase_name = f"seed{seed}_{pname}"
                print(f"[{exp_id}] ({run_idx}/{total_runs}) {phase_name} @ {fixed_pps:.0f} pps ...", flush=True)

                # Switch controller to fast NoAI mode first to drain any saturated backlog cleanly
                rpc_call(
                    ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]),
                    {"cmd": "configure_pipeline", "name": "drain", "extractor_mode": "none", "model_path": None},
                    timeout=15.0,
                )
                time.sleep(cooldown_s)
                prev_pi = -1
                for _ in range(12):
                    snap_q = rpc_call(
                        ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]),
                        {"cmd": "snapshot_phase"}, timeout=10.0,
                    )["snapshot"]
                    cur_pi = int(snap_q["packet_in_total"])
                    if cur_pi == prev_pi:
                        break
                    prev_pi = cur_pi
                    time.sleep(0.3)

                flush_dynamic_flows(["s1", "s2"], str(topo_cfg["openflow_version"]))
                rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "reinstall_table_miss"})

                # Configure active pipeline for this trial
                tier_name = pipe.get("tier")
                model_name = pipe.get("model")
                mpath = model_paths.get(f"{tier_name}__{model_name}") if (tier_name and model_name) else None
                fnames = tiers.get(tier_name) if tier_name else None
                rpc_call(
                    ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]),
                    {
                        "cmd": "configure_pipeline",
                        "name": pname,
                        "extractor_mode": str(pipe["extractor_mode"]),
                        "model_path": mpath,
                        "feature_names": fnames,
                    },
                    timeout=20.0,
                )
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
                    "--dst-ip", server_ip, "--dst-port", str(load_cfg["dst_port"]),
                    "--rate-pps", str(fixed_pps), "--duration", str(duration_s),
                    "--payload-bytes", str(load_cfg["payload_bytes"]), "--seed", str(trial_seed),
                ]
                if pin_cfg.get("enabled"):
                    gen_cmd = ["taskset", "-c", str(pin_cfg["generator_cores"]), *gen_cmd]

                iperf_p = h_benign.popen(iperf_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                ping_p = h_benign.popen(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                probe_p = h_benign.popen(probe_cmd, env=controller_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                gen_proc_holder["proc"] = h_attacker.popen(gen_cmd, env=controller_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                iperf_out, _ = iperf_p.communicate(timeout=duration_s + 25)
                ping_out, _ = ping_p.communicate(timeout=duration_s + 25)
                probe_out, _ = probe_p.communicate(timeout=duration_s + 25)
                gen_out, _ = gen_proc_holder["proc"].communicate(timeout=duration_s + 25)

                stop_mon.set()
                mon_thread.join(timeout=3.0)

                ctrl_snap = rpc_call(
                    ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]),
                    {"cmd": "snapshot_phase"}, timeout=25.0,
                )["snapshot"]

                iperf_stats = parse_iperf3_json(iperf_out, protocol="udp")
                ping_stats = parse_ping_output(ping_out)
                probe_stats = json.loads(probe_out.strip().splitlines()[-1]) if probe_out.strip() else {
                    "success_rate_pct": 0.0, "setup_latency_ms": summarize_distribution([])
                }
                gen_stats = json.loads(gen_out.strip().splitlines()[-1]) if gen_out.strip() else {"achieved_pps": 0.0}

                ctrl_cpus = [s["controller_cpu_pct"] for s in res_samples if s["controller_cpu_pct"] is not None]
                ctrl_rss = [s["controller_rss_mb"] for s in res_samples if s["controller_rss_mb"] is not None]
                ovs_cpus = [s["ovs_cpu_pct"] for s in res_samples if s["ovs_cpu_pct"] is not None]
                s1_flows = [s["s1_flows"] for s in res_samples if s["s1_flows"] >= 0]
                s1_peak = max(s1_flows) if s1_flows else 0

                tot = ctrl_snap["total_handler_ms"]
                base = ctrl_snap["base_ofp_ms"]
                feat = ctrl_snap["feature_extract_ms"]
                inf = ctrl_snap["model_infer_ms"]
                lag = ctrl_snap["event_loop_lag_ms"]
                pl = probe_stats["setup_latency_ms"]

                row = {
                    "seed": seed,
                    "pipeline": pname,
                    "extractor_mode": str(pipe["extractor_mode"]),
                    "model": str(model_name or "none"),
                    "achieved_spoof_pps": round(float(gen_stats.get("achieved_pps", 0.0)), 2),
                    "controller_packet_in_pps": round(float(ctrl_snap["packet_in_rate_pps"]), 2),
                    "controller_packet_in_total": int(ctrl_snap["packet_in_total"]),
                    "predicted_attack_total": int(ctrl_snap["predicted_attack_total"]),
                    "predicted_normal_total": int(ctrl_snap["predicted_normal_total"]),
                    "base_ofp_p50_ms": round(base["p50"], 4) if base["p50"] is not None else None,
                    "feature_extract_p50_ms": round(feat["p50"], 4) if feat["p50"] is not None else None,
                    "feature_extract_p95_ms": round(feat["p95"], 4) if feat["p95"] is not None else None,
                    "model_infer_p50_ms": round(inf["p50"], 4) if inf["p50"] is not None else None,
                    "model_infer_p95_ms": round(inf["p95"], 4) if inf["p95"] is not None else None,
                    "total_handler_p50_ms": round(tot["p50"], 4) if tot["p50"] is not None else None,
                    "total_handler_p95_ms": round(tot["p95"], 4) if tot["p95"] is not None else None,
                    "total_handler_p99_ms": round(tot["p99"], 4) if tot["p99"] is not None else None,
                    "event_loop_lag_p95_ms": round(lag["p95"], 3) if lag["p95"] is not None else None,
                    "controller_cpu_mean_pct": round(sum(ctrl_cpus) / len(ctrl_cpus), 2) if ctrl_cpus else None,
                    "controller_rss_peak_mb": round(max(ctrl_rss), 2) if ctrl_rss else None,
                    "ovs_cpu_mean_pct": round(sum(ovs_cpus) / len(ovs_cpus), 2) if ovs_cpus else None,
                    "s1_flow_table_occupancy_pct": round(100.0 * s1_peak / flow_limit, 2),
                    "benign_iperf_mbps": round(float(iperf_stats["goodput_mbps"]), 2),
                    "benign_ping_p95_ms": round(ping_stats["rtt_ms"]["p95"], 3) if ping_stats["rtt_ms"]["p95"] is not None else None,
                    "benign_new_flow_success_pct": round(float(probe_stats["success_rate_pct"]), 2),
                    "benign_new_flow_p95_ms": round(pl["p95"], 3) if pl["p95"] is not None else None,
                }
                trial_rows.append(row)
                print(
                    f"  -> pi={row['controller_packet_in_pps']:6.1f} pps | base={row['base_ofp_p50_ms']:.3f} feat={row['feature_extract_p50_ms']:.3f} "
                    f"infer={row['model_infer_p50_ms']:.3f} tot_p99={row['total_handler_p99_ms']:.3f} ms | "
                    f"lag_p95={row['event_loop_lag_p95_ms']:5.2f} ms | cpu={row['controller_cpu_mean_pct']:5.1f}% | "
                    f"new_flow_ok={row['benign_new_flow_success_pct']:5.1f}% (p95={row['benign_new_flow_p95_ms']} ms)",
                    flush=True,
                )

        # Aggregate across seeds per pipeline
        for pipe in pipelines:
            pname = str(pipe["name"])
            subset = [r for r in trial_rows if r["pipeline"] == pname]
            tier_name = pipe.get("tier")
            model_name = pipe.get("model")
            off = offline_scores.get(f"{tier_name}__{model_name}", {})
            agg: dict[str, Any] = {
                "pipeline": pname,
                "extractor_mode": str(pipe["extractor_mode"]),
                "model": str(model_name or "none"),
                "n_seeds": len(subset),
                "offline_test_macro_f1": off.get("test_macro_f1"),
                "offline_test_fpr": off.get("test_fpr"),
            }
            for metric in (
                "controller_packet_in_pps",
                "base_ofp_p50_ms",
                "feature_extract_p50_ms",
                "feature_extract_p95_ms",
                "model_infer_p50_ms",
                "model_infer_p95_ms",
                "total_handler_p50_ms",
                "total_handler_p99_ms",
                "event_loop_lag_p95_ms",
                "controller_cpu_mean_pct",
                "controller_rss_peak_mb",
                "ovs_cpu_mean_pct",
                "benign_new_flow_success_pct",
                "benign_new_flow_p95_ms",
            ):
                m, _, ci = mean_ci95([r[metric] for r in subset if r[metric] is not None])
                agg[f"{metric}_mean"] = round(m, 4) if m is not None else None
                agg[f"{metric}_ci95"] = round(ci, 4) if ci is not None else None
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
        by_name = {r["pipeline"]: r for r in agg_rows}
        a = by_name.get("Baseline_A_NoAI", {})
        lgb = by_name.get("Baseline_B_T1a_LGBM", {})
        rf3 = by_name.get("Baseline_C_T3_RF", {})
        primary_summary = (
            f"NoAI cpu={a.get('controller_cpu_mean_pct_mean')}% (ok={a.get('benign_new_flow_success_pct_mean')}%) | "
            f"T1a+LGBM cpu={lgb.get('controller_cpu_mean_pct_mean')}% (ok={lgb.get('benign_new_flow_success_pct_mean')}%, feat={lgb.get('feature_extract_p50_ms_mean')}ms, inf={lgb.get('model_infer_p50_ms_mean')}ms) | "
            f"T3+RF cpu={rf3.get('controller_cpu_mean_pct_mean')}% (ok={rf3.get('benign_new_flow_success_pct_mean')}%, feat={rf3.get('feature_extract_p50_ms_mean')}ms, inf={rf3.get('model_infer_p50_ms_mean')}ms)"
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
        "dataset": {
            "name": ds_manifest["dataset_name"],
            "sha256": ds_manifest["sha256"],
        },
        "container_trained_offline_scores": offline_scores,
        "cpu_pinning_applied": pinning_applied,
        "topology_runtime": topo_meta,
        "environment": env_meta,
        "pre_test_connectivity_loss_pct": connectivity_loss_pct,
        "result_summary": primary_summary,
        "limitations": [
            "Observe-only profiling (no active packet dropping) so every pipeline experiences identical Packet-In arrival load for unbiased component attribution; active mitigation evaluated in Phase 5.",
            "OVS datapath mode: netdev userspace (isolated from controller via taskset core pinning).",
            "InSDN models evaluated on live synthetic Mininet traffic experience offline-to-live domain shift (prediction totals logged transparently).",
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
            "notes": failure_reason if failure_reason else f"Completed {len(trial_rows)} core-pinned live component-profiling trials across {len(seeds)} seeds.",
        },
    )
    if status != "SUCCESS":
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run EXP-0007 Live SDN Component Profiling")
    parser.add_argument("--config", type=Path, default=REPO_ROOT / "configs" / "exp0007_live_component_profiling.yaml")
    args = parser.parse_args()
    run_experiment(args.config.resolve())


if __name__ == "__main__":
    main()
