"""Runner for EXP-0008: Live Multi-Regime OpenFlow Window Telemetry & Stage-2 Training.

Collects real 250 ms OpenFlow windows from Mininet + os-ken across benign steady,
benign TCP flash crowds (40 & 80 conn/s), variable-payload spoofed UDP floods, and
spoofed TCP SYN floods on strictly disjoint Train [101, 102] vs. Test [201, 202] seeds.
Trains Stage-2 LightGBM and compares against Logistic Regression and Static Rate Threshold.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import yaml
from lightgbm import LGBMClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from evaluation.metrics import (  # noqa: E402
    append_registry_row,
    collect_environment_metadata,
    ensure_non_overwrite,
    get_git_commit,
    sha256_file,
    write_manifest,
)
from features.window_features import WINDOW_FEATURE_NAMES  # noqa: E402
from models.offline_baselines import compute_classification_metrics, set_single_thread_inference  # noqa: E402
from scripts.run_exp0001_baseline_no_ai import find_pid_by_name, rpc_call, wait_for_controller  # noqa: E402
from scripts.run_exp0003_latency_budget import pin_pid  # noqa: E402
from topology.minimal_topology import HOST_SPECS, build_minimal_network, flush_dynamic_flows  # noqa: E402


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

    ctrl_cfg = cfg["controller"]
    topo_cfg = cfg["topology"]
    col_cfg = cfg["collection"]
    pin_cfg = cfg.get("cpu_pinning", {})
    train_seeds = [int(s) for s in cfg["train_seeds"]]
    test_seeds = [int(s) for s in cfg["test_seeds"]]

    controller_env = os.environ.copy()
    controller_env["PYTHONPATH"] = f"{REPO_ROOT / 'src'}:{controller_env.get('PYTHONPATH', '')}"
    controller_env["SDN_TELEMETRY_PORT"] = str(ctrl_cfg["telemetry_port"])
    controller_env["SDN_WINDOW_INTERVAL_MS"] = str(ctrl_cfg["window_interval_ms"])
    controller_env["SDN_FLOW_IDLE_TIMEOUT"] = str(topo_cfg["flow_idle_timeout_s"])
    controller_env["SDN_FLOW_HARD_TIMEOUT"] = str(topo_cfg["flow_hard_timeout_s"])
    controller_env["OMP_NUM_THREADS"] = "1"

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
    all_rows: list[dict[str, Any]] = []
    eval_summary: list[dict[str, Any]] = []
    status = "FAILED"
    failure_reason = ""
    topo_meta: dict[str, Any] = {}

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
            pin_pid(ctrl_pid, str(pin_cfg["controller_cores"]))
            pin_pid(ovs_pid, str(pin_cfg["ovs_cores"]))

        loss = float(net.pingAll(timeout="2"))
        if loss > 0.0:
            raise RuntimeError(f"Pre-test pingAll loss={loss}%")

        rpc_call(
            ctrl_cfg["host"],
            int(ctrl_cfg["telemetry_port"]),
            {
                "cmd": "configure",
                "mode": "collector",
                "window_interval_ms": ctrl_cfg["window_interval_ms"],
                "edge_ports": ctrl_cfg["edge_ports"],
            },
        )

        h_benign = net.get("h_benign")
        h_attacker = net.get("h_attacker")
        h_server = net.get("h_server")
        iperf_srv = h_server.popen(["iperf3", "-s"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        echo_srv = h_server.popen(
            ["python3", str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"), "echo_server", "--port", str(col_cfg["echo_port"])],
            env=controller_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(0.5)

        server_ip = HOST_SPECS["h_server"]["ip"].split("/")[0]
        attacker_mac = HOST_SPECS["h_attacker"]["mac"]
        server_mac = HOST_SPECS["h_server"]["mac"]
        attacker_iface = h_attacker.defaultIntf().name
        dur_s = float(col_cfg["phase_duration_s"])
        cd_s = float(col_cfg["cooldown_s"])

        for split_name, seeds in (("train", train_seeds), ("test", test_seeds)):
            for seed in seeds:
                for reg_idx, reg in enumerate(col_cfg["regimes"]):
                    rname = str(reg["name"])
                    rkind = str(reg["kind"])
                    rlabel = int(reg["label"])
                    trial_seed = seed * 100 + reg_idx
                    print(f"[{exp_id}] Collecting split={split_name} seed={seed} regime={rname} ...", flush=True)

                    time.sleep(cd_s)
                    flush_dynamic_flows(["s1", "s2"], str(topo_cfg["openflow_version"]))
                    rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "reinstall_table_miss"})
                    rpc_call(ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]), {"cmd": "reset_phase", "phase_name": f"{split_name}_{seed}_{rname}"})

                    procs = []
                    # Always run background benign probe + steady UDP on h_benign (port 1)
                    procs.append(
                        h_benign.popen(
                            ["iperf3", "-c", server_ip, "-u", "-b", "20M", "-t", str(int(dur_s)), "-J"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                        )
                    )
                    if rkind == "benign_steady":
                        procs.append(
                            h_benign.popen(
                                [
                                    "python3", str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"), "new_flow_probe",
                                    "--dst-ip", server_ip, "--dst-port", str(col_cfg["echo_port"]),
                                    "--rate-hz", "2.0", "--duration", str(dur_s), "--timeout", "2.0",
                                ],
                                env=controller_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            )
                        )
                    elif rkind == "flash_crowd":
                        procs.append(
                            h_benign.popen(
                                [
                                    "python3", str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"), "flash_crowd",
                                    "--dst-ip", server_ip, "--dst-port", str(col_cfg["echo_port"]),
                                    "--rate-hz", str(reg["rate_hz"]), "--duration", str(dur_s),
                                    "--concurrency", "32", "--seed", str(trial_seed),
                                ],
                                env=controller_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            )
                        )
                    elif rkind == "spoof_udp":
                        gen_cmd = [
                            "python3", str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"), "spoof_udp",
                            "--iface", attacker_iface, "--src-mac", attacker_mac, "--dst-mac", server_mac,
                            "--dst-ip", server_ip, "--dst-port", "9999",
                            "--rate-pps", str(reg["rate_pps"]), "--duration", str(dur_s),
                            "--min-payload-bytes", str(reg["min_payload_bytes"]),
                            "--max-payload-bytes", str(reg["max_payload_bytes"]),
                            "--seed", str(trial_seed),
                        ]
                        if pin_cfg.get("enabled"):
                            gen_cmd = ["taskset", "-c", str(pin_cfg["generator_cores"]), *gen_cmd]
                        procs.append(h_attacker.popen(gen_cmd, env=controller_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
                    elif rkind == "spoof_syn":
                        gen_cmd = [
                            "python3", str(REPO_ROOT / "src" / "evaluation" / "traffic_gen.py"), "spoof_syn",
                            "--iface", attacker_iface, "--src-mac", attacker_mac, "--dst-mac", server_mac,
                            "--dst-ip", server_ip, "--dst-port", str(col_cfg["echo_port"]),
                            "--rate-pps", str(reg["rate_pps"]), "--duration", str(dur_s),
                            "--seed", str(trial_seed),
                        ]
                        if pin_cfg.get("enabled"):
                            gen_cmd = ["taskset", "-c", str(pin_cfg["generator_cores"]), *gen_cmd]
                        procs.append(h_attacker.popen(gen_cmd, env=controller_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))

                    for p in procs:
                        p.communicate(timeout=dur_s + 20)

                    snap = rpc_call(
                        ctrl_cfg["host"], int(ctrl_cfg["telemetry_port"]),
                        {"cmd": "snapshot_phase", "include_windows": True}, timeout=15.0,
                    )["snapshot"]

                    # Label windows cleanly by true port role:
                    # port 1 = h_benign (always label 0); port 2 = h_attacker (label 1 during attack regimes)
                    added = 0
                    for w in snap.get("collected_windows", []):
                        port = int(w["in_port"])
                        if rlabel == 1 and port != 2:
                            # Benign background port 1 during an attack phase stays label 0
                            true_y = 0
                            true_reg = "benign_bg_during_attack"
                        elif rlabel == 1 and port == 2:
                            true_y = 1
                            true_reg = rname
                        else:
                            if port != 1:
                                continue
                            true_y = 0
                            true_reg = rname
                        all_rows.append(
                            {
                                "split": split_name,
                                "seed": seed,
                                "regime": true_reg,
                                "label": true_y,
                                "dpid": int(w["dpid"]),
                                "in_port": port,
                                "count": int(w["count"]),
                                **{fn: float(w[fn]) for fn in WINDOW_FEATURE_NAMES},
                            }
                        )
                        added += 1
                    print(f"  -> collected {added} windows", flush=True)

        for p in (iperf_srv, echo_srv):
            try:
                p.terminate()
            except Exception:
                pass

        df = pd.DataFrame(all_rows)
        df.to_csv(results_dir / "window_telemetry_dataset.csv", index=False)

        df_tr = df[df["split"] == "train"].reset_index(drop=True)
        df_te = df[df["split"] == "test"].reset_index(drop=True)
        X_tr = df_tr[WINDOW_FEATURE_NAMES].to_numpy(dtype=np.float32)
        y_tr = df_tr["label"].to_numpy(dtype=int)
        X_te = df_te[WINDOW_FEATURE_NAMES].to_numpy(dtype=np.float32)
        y_te = df_te["label"].to_numpy(dtype=int)
        reg_te = df_te["regime"].to_numpy()
        flash_mask = np.isin(reg_te, ["benign_flash_40hz", "benign_flash_80hz"])
        udp_mask = np.isin(reg_te, ["attack_spoof_udp_150pps", "attack_spoof_udp_500pps"])
        syn_mask = np.isin(reg_te, ["attack_spoof_syn_150pps", "attack_spoof_syn_500pps"])

        print(f"\n[{exp_id}] Training Stage-2 models (train={len(df_tr)} windows, test={len(df_te)} windows) ...", flush=True)
        gate_pps = float(col_cfg["static_gate_pps"])

        # 1. Naive Static Rate Threshold Baseline (A4 control)
        rate_pred = (X_te[:, 0] >= gate_pps).astype(int)
        m_rate = compute_classification_metrics(y_te, rate_pred, X_te[:, 0])
        eval_summary.append(
            {
                "model": f"Static_Rate_Threshold(>={gate_pps:.0f}pps)",
                "test_macro_f1": round(m_rate["macro_f1"], 5),
                "test_fpr_all_benign": round(m_rate["fpr"], 5),
                "test_fpr_flash_crowd": round(float(rate_pred[flash_mask].mean()), 5) if flash_mask.any() else None,
                "test_recall_udp_flood": round(float(rate_pred[udp_mask].mean()), 5) if udp_mask.any() else None,
                "test_recall_syn_flood": round(float(rate_pred[syn_mask].mean()), 5) if syn_mask.any() else None,
            }
        )

        # 2. Logistic Regression
        lr = Pipeline([("scaler", StandardScaler()), ("clf", LogisticRegression(max_iter=500, class_weight="balanced", random_state=42))])
        lr.fit(X_tr, y_tr)
        lr_prob = lr.predict_proba(X_te)[:, 1]
        lr_pred = (lr_prob >= 0.5).astype(int)
        m_lr = compute_classification_metrics(y_te, lr_pred, lr_prob)
        eval_summary.append(
            {
                "model": "Window_LogisticRegression",
                "test_macro_f1": round(m_lr["macro_f1"], 5),
                "test_fpr_all_benign": round(m_lr["fpr"], 5),
                "test_fpr_flash_crowd": round(float(lr_pred[flash_mask].mean()), 5) if flash_mask.any() else None,
                "test_recall_udp_flood": round(float(lr_pred[udp_mask].mean()), 5) if udp_mask.any() else None,
                "test_recall_syn_flood": round(float(lr_pred[syn_mask].mean()), 5) if syn_mask.any() else None,
            }
        )

        # 3. Stage-2 Lightweight LightGBM
        lgbm = LGBMClassifier(
            n_estimators=60, max_depth=5, num_leaves=15, learning_rate=0.1,
            class_weight="balanced", random_state=42, n_jobs=1, verbose=-1,
        )
        lgbm.fit(X_tr, y_tr)
        set_single_thread_inference(lgbm)
        lgb_prob = lgbm.predict_proba(X_te)[:, 1]
        lgb_pred = (lgb_prob >= 0.5).astype(int)
        m_lgb = compute_classification_metrics(y_te, lgb_pred, lgb_prob)
        eval_summary.append(
            {
                "model": "Stage2_Window_LightGBM",
                "test_macro_f1": round(m_lgb["macro_f1"], 5),
                "test_fpr_all_benign": round(m_lgb["fpr"], 5),
                "test_fpr_flash_crowd": round(float(lgb_pred[flash_mask].mean()), 5) if flash_mask.any() else None,
                "test_recall_udp_flood": round(float(lgb_pred[udp_mask].mean()), 5) if udp_mask.any() else None,
                "test_recall_syn_flood": round(float(lgb_pred[syn_mask].mean()), 5) if syn_mask.any() else None,
            }
        )

        joblib.dump(
            {"model": lgbm, "features": WINDOW_FEATURE_NAMES, "window_ms": ctrl_cfg["window_interval_ms"]},
            artifacts_dir / "stage2_window_lgbm.joblib",
        )
        joblib.dump(
            {"model": lr, "features": WINDOW_FEATURE_NAMES, "window_ms": ctrl_cfg["window_interval_ms"]},
            artifacts_dir / "stage2_window_lr.joblib",
        )

        with (results_dir / "stage2_evaluation_summary.csv").open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(eval_summary[0].keys()))
            writer.writeheader()
            writer.writerows(eval_summary)

        for r in eval_summary:
            print(
                f"  {r['model']:<34s} | MacroF1={r['test_macro_f1']:.4f} | FPR_all={r['test_fpr_all_benign']*100:5.2f}% | "
                f"FPR_flash={r['test_fpr_flash_crowd']*100:5.2f}% | Rec_UDP={r['test_recall_udp_flood']*100:5.1f}% | Rec_SYN={r['test_recall_syn_flood']*100:5.1f}%",
                flush=True,
            )

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

    primary_summary = "FAILED"
    if eval_summary:
        s_rate = eval_summary[0]
        s_lgb = eval_summary[-1]
        primary_summary = (
            f"StaticRate(>=30pps): F1={s_rate['test_macro_f1']}, FlashCrowd_FPR={s_rate['test_fpr_flash_crowd']*100:.1f}% | "
            f"Stage2_Window_LGBM: F1={s_lgb['test_macro_f1']}, FlashCrowd_FPR={s_lgb['test_fpr_flash_crowd']*100:.1f}%, "
            f"UDP_Rec={s_lgb['test_recall_udp_flood']*100:.1f}%, SYN_Rec={s_lgb['test_recall_syn_flood']*100:.1f}%"
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
        "windows_collected_total": len(all_rows),
        "evaluation_summary": eval_summary,
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
            "notes": failure_reason if failure_reason else f"Collected {len(all_rows)} live windows on disjoint train/test seeds; saved Stage-2 LGBM.",
        },
    )
    if status != "SUCCESS":
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run EXP-0008 Live Multi-Regime Telemetry & Stage-2 Training")
    parser.add_argument("--config", type=Path, default=REPO_ROOT / "configs" / "exp0008_window_telemetry.yaml")
    args = parser.parse_args()
    run_experiment(args.config.resolve())


if __name__ == "__main__":
    main()
