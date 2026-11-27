"""Out-of-process decoupled Stage-2 ML inference worker (separate OS process & Python GIL).

Uses a direct multiprocessing.Pipe (zero background QueueFeederThread) so parent-side
calls are 100% non-blocking and safe inside eventlet-monkey-patched os-ken controllers.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import time
from typing import Any

import joblib
import numpy as np


def _worker_loop(
    model_path: str,
    conn: Any,
    pin_core: int | None,
    max_batch_size: int,
    attack_threshold: float,
) -> None:
    """Child OS process executing single-threaded micro-batched Stage-2 ML classification."""
    os.environ["OMP_NUM_THREADS"] = "1"
    os.environ["OPENBLAS_NUM_THREADS"] = "1"
    os.environ["MKL_NUM_THREADS"] = "1"

    if pin_core is not None and hasattr(os, "sched_setaffinity"):
        try:
            os.sched_setaffinity(0, {int(pin_core)})
        except Exception:
            pass

    bundle = joblib.load(model_path)
    model = bundle["model"] if isinstance(bundle, dict) and "model" in bundle else bundle
    if hasattr(model, "set_params"):
        params = model.get_params(deep=False)
        if "n_jobs" in params:
            model.set_params(n_jobs=1)

    # Warm up once at startup
    n_features = len(bundle["features"]) if isinstance(bundle, dict) and "features" in bundle else 10
    model.predict_proba(np.zeros((1, n_features), dtype=np.float32))
    conn.send({"type": "ready", "pid": os.getpid()})

    running = True
    while running:
        if not conn.poll(0.05):
            continue

        batch_items: list[dict[str, Any]] = []
        while len(batch_items) < max_batch_size and conn.poll(0):
            try:
                msg = conn.recv()
            except EOFError:
                running = False
                break
            if msg is None:
                running = False
                break
            batch_items.append(msg)

        if not batch_items:
            continue

        X_batch = np.vstack([np.asarray(it["vec"], dtype=np.float32) for it in batch_items])
        t0 = time.perf_counter_ns()
        probs = model.predict_proba(X_batch)[:, 1]
        infer_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        per_item_ms = infer_ms / len(batch_items)
        now_ns = time.perf_counter_ns()

        for item, p in zip(batch_items, probs):
            prob_f = float(p)
            conn.send(
                {
                    "type": "decision",
                    "dpid": item["dpid"],
                    "in_port": item["in_port"],
                    "dominant_proto": item["dominant_proto"],
                    "dominant_dst_ip": item["dominant_dst_ip"],
                    "prob": prob_f,
                    "is_attack": bool(prob_f >= attack_threshold),
                    "batch_size": len(batch_items),
                    "worker_infer_ms": per_item_ms,
                    "enqueued_ns": item["enqueued_ns"],
                    "decided_ns": now_ns,
                }
            )


class AsyncStage2Worker:
    """Parent-side eventlet-safe non-blocking handle managing the Stage-2 OS worker process."""

    def __init__(
        self,
        model_path: str,
        pin_core: int | None = None,
        max_batch_size: int = 32,
        attack_threshold: float = 0.5,
    ) -> None:
        self.model_path = model_path
        self.pin_core = pin_core
        self.max_batch_size = max_batch_size
        self.attack_threshold = attack_threshold
        self._ctx = mp.get_context("spawn")
        self._parent_conn: Any = None
        self._proc: mp.Process | None = None
        self.worker_pid: int | None = None

    def start(self, timeout_s: float = 15.0) -> int:
        parent_conn, child_conn = self._ctx.Pipe(duplex=True)
        self._parent_conn = parent_conn
        self._proc = self._ctx.Process(
            target=_worker_loop,
            args=(
                self.model_path,
                child_conn,
                self.pin_core,
                self.max_batch_size,
                self.attack_threshold,
            ),
            daemon=True,
        )
        self._proc.start()
        child_conn.close()

        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self._parent_conn.poll(0):
                msg = self._parent_conn.recv()
                if msg.get("type") != "ready":
                    raise RuntimeError(f"Unexpected worker startup message: {msg}")
                self.worker_pid = int(msg["pid"])
                return self.worker_pid
            time.sleep(0.05)
        raise TimeoutError(f"Stage-2 worker did not become ready within {timeout_s}s")

    def submit_nonblocking(
        self,
        dpid: int,
        in_port: int,
        vec: np.ndarray,
        dominant_proto: int,
        dominant_dst_ip: str,
    ) -> bool:
        """Send a window feature vector to the worker process without blocking."""
        if self._parent_conn is None:
            return False
        payload = {
            "dpid": int(dpid),
            "in_port": int(in_port),
            "vec": np.asarray(vec, dtype=np.float32).reshape(1, -1),
            "dominant_proto": int(dominant_proto),
            "dominant_dst_ip": str(dominant_dst_ip),
            "enqueued_ns": time.perf_counter_ns(),
        }
        try:
            self._parent_conn.send(payload)
            return True
        except Exception:
            return False

    def poll_decisions(self, max_items: int = 64) -> list[dict[str, Any]]:
        """Drain all currently available mitigation decisions without blocking."""
        if self._parent_conn is None:
            return []
        out: list[dict[str, Any]] = []
        for _ in range(max_items):
            if not self._parent_conn.poll(0):
                break
            try:
                msg = self._parent_conn.recv()
                if isinstance(msg, dict) and msg.get("type") == "decision":
                    out.append(msg)
            except EOFError:
                break
        return out

    def stop(self) -> None:
        if self._parent_conn is not None:
            try:
                self._parent_conn.send(None)
            except Exception:
                pass
            try:
                self._parent_conn.close()
            except Exception:
                pass
            self._parent_conn = None
        if self._proc is not None:
            self._proc.join(timeout=3.0)
            if self._proc.is_alive():
                self._proc.terminate()
            self._proc = None
