"""Metrics aggregation, environment capture, and append-only experiment logging."""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

import numpy as np


REGISTRY_COLUMNS = [
    "experiment_id",
    "timestamp_utc",
    "git_commit",
    "phase",
    "status",
    "hypothesis_id",
    "objective",
    "environment_mode",
    "primary_metric_summary",
    "manifest_path",
    "results_path",
    "notes",
]


def summarize_distribution(values: list[float] | np.ndarray) -> dict[str, float | int | None]:
    """Compute robust summary statistics including median, p95, and p99."""
    arr = np.asarray(values, dtype=np.float64)
    if arr.size == 0:
        return {
            "count": 0,
            "mean": None,
            "std": None,
            "min": None,
            "p50": None,
            "p95": None,
            "p99": None,
            "max": None,
        }
    return {
        "count": int(arr.size),
        "mean": float(np.mean(arr)),
        "std": float(np.std(arr, ddof=0)),
        "min": float(np.min(arr)),
        "p50": float(np.percentile(arr, 50)),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
        "max": float(np.max(arr)),
    }


def sha256_file(path: Path) -> str:
    """Return hex SHA-256 digest for a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def get_git_commit(repo_root: Path) -> dict[str, Any]:
    """Capture current git HEAD commit hash and dirty state."""
    def _run(args: list[str]) -> str:
        try:
            out = subprocess.check_output(
                ["git", "-c", f"safe.directory={repo_root}", *args],
                cwd=str(repo_root),
                stderr=subprocess.DEVNULL,
                text=True,
            )
            return out.strip()
        except Exception:
            return "unknown"

    commit = _run(["rev-parse", "HEAD"])
    status = _run(["status", "--porcelain"])
    return {
        "commit": commit,
        "dirty": bool(status) if status != "unknown" else None,
    }


def collect_environment_metadata() -> dict[str, Any]:
    """Capture hardware, kernel, OVS, and Python runtime metadata for reproducibility."""
    def _cmd(cmd: list[str]) -> str:
        try:
            return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True).strip()
        except Exception:
            return "unavailable"

    ovs_ver = _cmd(["ovs-vsctl", "--version"]).splitlines()[0] if _cmd(["ovs-vsctl", "--version"]) != "unavailable" else "unavailable"
    mn_ver = _cmd(["mn", "--version"])
    os_ken_ver = "unavailable"
    try:
        import importlib.metadata

        os_ken_ver = importlib.metadata.version("os-ken")
    except Exception:
        pass

    return {
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "kernel_release": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "cpu_count_logical": os.cpu_count(),
        "ovs_version": ovs_ver,
        "ovs_datapath_mode": os.environ.get("OVS_DATAPATH_MODE", "unknown"),
        "mininet_version": mn_ver,
        "os_ken_version": os_ken_ver,
    }


def ensure_non_overwrite(paths: list[Path]) -> None:
    """Guard against overwriting any previous experiment artifacts."""
    existing = [str(p) for p in paths if p.exists()]
    if existing:
        raise FileExistsError(
            "Refusing to overwrite existing experiment outputs: " + ", ".join(existing)
        )


def write_manifest(manifest_path: Path, payload: dict[str, Any]) -> None:
    """Write immutable JSON manifest for an experiment."""
    ensure_non_overwrite([manifest_path])
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)
        f.write("\n")


def append_registry_row(registry_path: Path, row: dict[str, Any]) -> None:
    """Append a structured experiment record to experiments/registry.csv."""
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not registry_path.exists() or registry_path.stat().st_size == 0
    with registry_path.open("a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=REGISTRY_COLUMNS)
        if write_header:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in REGISTRY_COLUMNS})
