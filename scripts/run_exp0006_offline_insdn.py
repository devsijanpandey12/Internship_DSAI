"""Runner for EXP-0006: Leakage-Free InSDN Baselines Across SDN Observability Tiers."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import yaml
from sklearn.model_selection import train_test_split

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from data.insdn_loader import load_clean_insdn  # noqa: E402
from evaluation.metrics import (  # noqa: E402
    append_registry_row,
    collect_environment_metadata,
    ensure_non_overwrite,
    get_git_commit,
    sha256_file,
    write_manifest,
)
from models.offline_baselines import (  # noqa: E402
    benchmark_inference_latency,
    build_model,
    compute_classification_metrics,
)


def run_experiment(config_path: Path) -> None:
    with config_path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    exp_id = str(cfg["experiment_id"])
    manifest_path = REPO_ROOT / "experiments" / "manifests" / f"{exp_id}.json"
    results_dir = REPO_ROOT / "experiments" / "results" / exp_id
    artifacts_dir = REPO_ROOT / "experiments" / "artifacts" / exp_id
    ensure_non_overwrite([manifest_path, results_dir, artifacts_dir])

    results_dir.mkdir(parents=True, exist_ok=False)
    artifacts_dir.mkdir(parents=True, exist_ok=False)

    env_meta = collect_environment_metadata()
    git_meta = get_git_commit(REPO_ROOT)

    ds_cfg = cfg["dataset"]
    raw_csv = REPO_ROOT / ds_cfg["raw_csv"]
    ds_manifest_path = REPO_ROOT / ds_cfg["manifest_json"]
    ds_manifest = json.loads(ds_manifest_path.read_text(encoding="utf-8"))

    seed = int(cfg["seed"])
    print(f"[{exp_id}] Loading and sanitizing InSDN ({raw_csv}) ...", flush=True)
    X_all, y_bin, y_mc, tiers = load_clean_insdn(
        raw_csv,
        include_dst_port=bool(ds_cfg["include_dst_port"]),
        deduplicate_features=bool(ds_cfg["deduplicate_features"]),
    )
    print(
        f"[{exp_id}] Clean deduplicated dataset: {len(X_all):,} rows x {X_all.shape[1]} features "
        f"(Normal={(y_bin == 0).sum():,}, Attack={(y_bin == 1).sum():,})",
        flush=True,
    )

    # Stratified 70 / 15 / 15 split on multi-class labels so rare attacks are stratified fairly
    idx_all = np.arange(len(X_all))
    strat_labels = y_mc.to_numpy()
    # Group ultra-rare classes (<10 samples) under fallback label only for stratification stability
    vals, counts = np.unique(strat_labels, return_counts=True)
    rare = set(vals[counts < 10])
    strat_safe = np.where(np.isin(strat_labels, list(rare)), "RARE_ATTACK", strat_labels)

    idx_train, idx_tmp = train_test_split(
        idx_all, test_size=0.30, random_state=seed, stratify=strat_safe
    )
    idx_val, idx_test = train_test_split(
        idx_tmp, test_size=0.50, random_state=seed, stratify=strat_safe[idx_tmp]
    )

    y_train = y_bin.to_numpy()[idx_train]
    y_val = y_bin.to_numpy()[idx_val]
    y_test = y_bin.to_numpy()[idx_test]
    mc_test = y_mc.to_numpy()[idx_test]

    summary_rows: list[dict[str, Any]] = []
    detailed_results: list[dict[str, Any]] = []
    lat_cfg = cfg["latency_benchmark"]
    sync_budget_ms = float(lat_cfg["exp0005_sync_budget_ms"])

    for tier_name in cfg["tiers"]:
        cols = tiers[tier_name]
        X_tier = X_all[cols].to_numpy(dtype=np.float32)
        X_tr, X_va, X_te = X_tier[idx_train], X_tier[idx_val], X_tier[idx_test]

        print(f"\n[{exp_id}] === Tier: {tier_name} ({len(cols)} features) ===", flush=True)
        for model_name in cfg["models"]:
            t_fit0 = time.perf_counter()
            model = build_model(model_name, seed=seed, n_jobs_train=4)
            model.fit(X_tr, y_train)
            fit_s = time.perf_counter() - t_fit0

            # Validation & test classification metrics
            val_prob = model.predict_proba(X_va)[:, 1]
            val_pred = (val_prob >= 0.5).astype(int)
            val_metrics = compute_classification_metrics(y_val, val_pred, val_prob)

            test_prob = model.predict_proba(X_te)[:, 1]
            test_pred = (test_prob >= 0.5).astype(int)
            test_metrics = compute_classification_metrics(y_test, test_pred, test_prob, mc_test)

            # Reactive batch=1 vs. micro-batch=64 single-thread CPU inference latency
            lat = benchmark_inference_latency(
                model,
                X_te,
                n_single=int(lat_cfg["n_single"]),
                batch_size=int(lat_cfg["batch_size"]),
                n_batches=int(lat_cfg["n_batches"]),
                warmup=int(lat_cfg["warmup"]),
            )
            b1 = lat["batch1_ms"]
            b64 = lat["batch64_per_flow_ms"]
            speedup = (b1["p50"] / b64["p50"]) if (b1["p50"] and b64["p50"]) else None

            # Save model artifact for Phase 4B live SDN deployment
            artifact_path = artifacts_dir / f"{tier_name}__{model_name}.joblib"
            joblib.dump({"model": model, "features": cols, "tier": tier_name, "model_name": model_name}, artifact_path)
            artifact_kb = artifact_path.stat().st_size / 1024.0

            row = {
                "tier": tier_name,
                "n_features": len(cols),
                "model": model_name,
                "train_time_s": round(fit_s, 3),
                "artifact_kb": round(artifact_kb, 1),
                "val_macro_f1": round(val_metrics["macro_f1"], 5),
                "test_macro_f1": round(test_metrics["macro_f1"], 5),
                "test_attack_f1": round(test_metrics["attack_f1"], 5),
                "test_precision": round(test_metrics["precision"], 5),
                "test_recall": round(test_metrics["recall"], 5),
                "test_fpr": round(test_metrics["fpr"], 5),
                "test_pr_auc": round(test_metrics["pr_auc"], 5) if test_metrics["pr_auc"] is not None else None,
                "batch1_p50_ms": round(b1["p50"], 4),
                "batch1_p95_ms": round(b1["p95"], 4),
                "batch1_p99_ms": round(b1["p99"], 4),
                "batch64_per_flow_p50_ms": round(b64["p50"], 5),
                "batch64_per_flow_p95_ms": round(b64["p95"], 5),
                "batching_speedup_x": round(speedup, 2) if speedup else None,
                "exceeds_exp0005_1ms_p95": bool(b1["p95"] > sync_budget_ms),
            }
            summary_rows.append(row)
            detailed_results.append(
                {
                    "summary": row,
                    "features": cols,
                    "val_metrics": val_metrics,
                    "test_metrics": test_metrics,
                    "latency": lat,
                }
            )
            print(
                f"  {model_name:<20s} | Test F1={row['test_macro_f1']:.4f} | FPR={row['test_fpr']*100:5.2f}% | "
                f"b1 p50/p95/p99={row['batch1_p50_ms']:.3f}/{row['batch1_p95_ms']:.3f}/{row['batch1_p99_ms']:.3f} ms | "
                f"b64/flow p50={row['batch64_per_flow_p50_ms']:.4f} ms ({row['batching_speedup_x']}x) | "
                f"exceeds_1ms={row['exceeds_exp0005_1ms_p95']}",
                flush=True,
            )

    # Optional Dst Port leakage ablation on T1a + LightGBM & LR
    dst_port_ablation_res: list[dict[str, Any]] = []
    if ds_cfg.get("dst_port_ablation"):
        print(f"\n[{exp_id}] === Dst Port Shortcut Ablation (T1a + Dst Port) ===", flush=True)
        X_dp, y_dp_bin, y_dp_mc, tiers_dp = load_clean_insdn(
            raw_csv, include_dst_port=True, deduplicate_features=bool(ds_cfg["deduplicate_features"])
        )
        strat_dp = y_dp_mc.to_numpy()
        vals_dp, cnts_dp = np.unique(strat_dp, return_counts=True)
        rare_dp = set(vals_dp[cnts_dp < 10])
        strat_dp_safe = np.where(np.isin(strat_dp, list(rare_dp)), "RARE_ATTACK", strat_dp)
        i_tr, i_tmp = train_test_split(np.arange(len(X_dp)), test_size=0.30, random_state=seed, stratify=strat_dp_safe)
        _, i_te = train_test_split(i_tmp, test_size=0.50, random_state=seed, stratify=strat_dp_safe[i_tmp])
        for mname in ("logistic_regression", "lightgbm"):
            cols_dp = tiers_dp["T1a_Unidirectional_OF"]
            X_t = X_dp[cols_dp].to_numpy(dtype=np.float32)
            m = build_model(mname, seed=seed, n_jobs_train=4)
            m.fit(X_t[i_tr], y_dp_bin.to_numpy()[i_tr])
            probs = m.predict_proba(X_t[i_te])[:, 1]
            preds = (probs >= 0.5).astype(int)
            met = compute_classification_metrics(y_dp_bin.to_numpy()[i_te], preds, probs, y_dp_mc.to_numpy()[i_te])
            rec = {
                "tier": "T1a_Unidirectional_OF+DstPort",
                "model": mname,
                "n_features": len(cols_dp),
                "test_macro_f1": round(met["macro_f1"], 5),
                "test_fpr": round(met["fpr"], 5),
            }
            dst_port_ablation_res.append(rec)
            print(f"  {mname:<20s} (+Dst Port) | Test F1={rec['test_macro_f1']:.4f} | FPR={rec['test_fpr']*100:.2f}%", flush=True)

    # Save structured results
    summary_csv = results_dir / "offline_benchmark_summary.csv"
    with summary_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
        writer.writeheader()
        writer.writerows(summary_rows)

    with (results_dir / "detailed_results.json").open("w", encoding="utf-8") as f:
        json.dump({"runs": detailed_results, "dst_port_ablation": dst_port_ablation_res}, f, indent=2)

    best_f1 = max(summary_rows, key=lambda r: r["test_macro_f1"])
    fastest_t1a = min([r for r in summary_rows if r["tier"] == "T1a_Unidirectional_OF"], key=lambda r: r["batch1_p95_ms"])
    exceeding = sum(1 for r in summary_rows if r["exceeds_exp0005_1ms_p95"])
    primary_summary = (
        f"{len(summary_rows)} configs (4 tiers x 5 models); best F1={best_f1['test_macro_f1']} ({best_f1['tier']}/{best_f1['model']}); "
        f"fastest T1a b1_p95={fastest_t1a['batch1_p95_ms']}ms ({fastest_t1a['model']}); "
        f"{exceeding}/{len(summary_rows)} exceed EXP-0005 1ms sync p95 budget"
    )

    manifest = {
        "experiment_id": exp_id,
        "timestamp_utc": env_meta["timestamp_utc"],
        "status": "SUCCESS",
        "phase": cfg["phase"],
        "hypothesis_id": cfg["hypothesis_id"],
        "objective": cfg["objective"].strip(),
        "git": git_meta,
        "config_path": str(config_path.relative_to(REPO_ROOT)),
        "config_sha256": sha256_file(config_path),
        "config": cfg,
        "dataset": {
            "name": ds_manifest["dataset_name"],
            "source_url": ds_manifest["source_url"],
            "sha256": ds_manifest["sha256"],
            "raw_rows": ds_manifest["audit"]["n_rows"],
            "clean_dedup_rows": int(len(X_all)),
            "train_rows": int(len(idx_train)),
            "val_rows": int(len(idx_val)),
            "test_rows": int(len(idx_test)),
        },
        "tier_columns": tiers,
        "environment": env_meta,
        "result_summary": primary_summary,
        "limitations": [
            "Offline InSDN features come from post-hoc CICFlowMeter captures; live feature extraction overhead is measured separately in Phase 4B inside os-ken.",
            "Single-sample latency measured in isolated Windows Python 3.11 .venv; live Linux container latency inside os-ken will also include OpenFlow parsing and eventlet scheduling.",
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
            "status": "SUCCESS",
            "hypothesis_id": cfg["hypothesis_id"],
            "objective": cfg["objective"].strip(),
            "environment_mode": "local_venv_python311_cpu_singlethread",
            "primary_metric_summary": primary_summary,
            "manifest_path": str(manifest_path.relative_to(REPO_ROOT)),
            "results_path": str(results_dir.relative_to(REPO_ROOT)),
            "notes": f"Saved {len(summary_rows)} model artifacts under experiments/artifacts/{exp_id} for live SDN deployment.",
        },
    )
    print(f"\n[{exp_id}] DONE -> {primary_summary}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run EXP-0006 Offline InSDN Baselines")
    parser.add_argument("--config", type=Path, default=REPO_ROOT / "configs" / "exp0006_offline_insdn_baselines.yaml")
    args = parser.parse_args()
    run_experiment(args.config.resolve())


if __name__ == "__main__":
    main()
