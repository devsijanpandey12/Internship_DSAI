"""Offline ML/DL baseline models and single-sample vs. micro-batch CPU latency benchmarking."""

from __future__ import annotations

import time
from typing import Any

import numpy as np
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from evaluation.metrics import summarize_distribution


def build_model(model_name: str, seed: int = 42, n_jobs_train: int = 4) -> Any:
    """Instantiate a controlled baseline classifier (inference forced single-threaded later)."""
    if model_name == "logistic_regression":
        return Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=500,
                        class_weight="balanced",
                        random_state=seed,
                        solver="lbfgs",
                    ),
                ),
            ]
        )
    if model_name == "lightgbm":
        return LGBMClassifier(
            n_estimators=100,
            max_depth=8,
            num_leaves=31,
            learning_rate=0.1,
            class_weight="balanced",
            random_state=seed,
            n_jobs=n_jobs_train,
            verbose=-1,
        )
    if model_name == "xgboost":
        return XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="logloss",
            random_state=seed,
            n_jobs=n_jobs_train,
            tree_method="hist",
        )
    if model_name == "random_forest":
        return RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            class_weight="balanced_subsample",
            random_state=seed,
            n_jobs=n_jobs_train,
        )
    if model_name == "mlp":
        return Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "clf",
                    MLPClassifier(
                        hidden_layer_sizes=(128, 64),
                        activation="relu",
                        batch_size=256,
                        max_iter=25,
                        early_stopping=True,
                        n_iter_no_change=5,
                        random_state=seed,
                    ),
                ),
            ]
        )
    raise ValueError(f"Unknown model_name: {model_name}")


def set_single_thread_inference(model: Any) -> None:
    """Force single-threaded inference to match single-core reactive os-ken deployment."""
    if hasattr(model, "set_params"):
        params = model.get_params(deep=False)
        if "n_jobs" in params:
            model.set_params(n_jobs=1)
        if "nthread" in params:
            model.set_params(nthread=1)


def compute_classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray | None,
    multiclass_labels: np.ndarray | None = None,
) -> dict[str, Any]:
    """Compute binary F1, Macro F1, Precision, Recall, FPR, PR-AUC, and per-attack-class recall."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    metrics: dict[str, Any] = {
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "attack_f1": float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "precision": float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "fpr": fpr,
        "pr_auc": float(average_precision_score(y_true, y_prob)) if y_prob is not None else None,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }
    if multiclass_labels is not None:
        per_class: dict[str, float] = {}
        for cls in sorted(set(str(c) for c in multiclass_labels)):
            mask = multiclass_labels == cls
            if cls.lower() == "normal":
                per_class[cls] = float((y_pred[mask] == 0).mean())
            else:
                per_class[cls] = float((y_pred[mask] == 1).mean())
        metrics["per_class_detection_rate"] = per_class
    return metrics


def benchmark_inference_latency(
    model: Any,
    X_sample: np.ndarray,
    n_single: int = 1000,
    batch_size: int = 64,
    n_batches: int = 200,
    warmup: int = 50,
) -> dict[str, Any]:
    """Benchmark reactive single-sample (batch=1) vs. micro-batched (batch=64) CPU latency."""
    set_single_thread_inference(model)
    X_arr = np.ascontiguousarray(X_sample, dtype=np.float32)
    n_rows = X_arr.shape[0]

    # Warmup
    for i in range(min(warmup, n_rows)):
        model.predict_proba(X_arr[i : i + 1])

    # Batch=1 reactive latency (simulates synchronous per-Packet-In inference)
    single_ms: list[float] = []
    for i in range(n_single):
        row = X_arr[i % n_rows : (i % n_rows) + 1]
        t0 = time.perf_counter_ns()
        model.predict_proba(row)
        single_ms.append((time.perf_counter_ns() - t0) / 1_000_000.0)

    # Batch=64 micro-batch latency (simulates decoupled batched inference worker)
    batch_total_ms: list[float] = []
    batch_per_flow_ms: list[float] = []
    for i in range(n_batches):
        start = (i * batch_size) % max(1, n_rows - batch_size)
        blk = X_arr[start : start + batch_size]
        t0 = time.perf_counter_ns()
        model.predict_proba(blk)
        dt_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        batch_total_ms.append(dt_ms)
        batch_per_flow_ms.append(dt_ms / len(blk))

    return {
        "batch1_ms": summarize_distribution(single_ms),
        "batch64_total_ms": summarize_distribution(batch_total_ms),
        "batch64_per_flow_ms": summarize_distribution(batch_per_flow_ms),
    }
