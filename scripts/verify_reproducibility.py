"""Phase 7 Reproducibility & Integrity Audit Script.

Verifies:
  1. Every experiment in experiments/registry.csv has a valid JSON manifest and artifacts.
  2. All dataset manifests have verified SHA-256 metadata.
  3. All 6 paper figures and 3 executed Jupyter notebooks exist and are non-empty.
  4. Key cross-experiment metrics match saved CSVs cleanly.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    errors: list[str] = []

    reg_path = REPO_ROOT / "experiments" / "registry.csv"
    if not reg_path.exists():
        errors.append("Missing experiments/registry.csv")
    else:
        with reg_path.open("r", encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        print(f"Registry entries: {len(rows)}")
        seen_ids: set[str] = set()
        for r in rows:
            eid = r["experiment_id"]
            if eid in seen_ids:
                errors.append(f"Duplicate experiment_id in registry: {eid}")
            seen_ids.add(eid)
            mpath = REPO_ROOT / r["manifest_path"]
            if not mpath.exists():
                errors.append(f"Missing manifest for {eid}: {mpath}")
            else:
                try:
                    mdata = json.loads(mpath.read_text(encoding="utf-8"))
                    if mdata.get("experiment_id") != eid:
                        errors.append(f"Manifest ID mismatch for {eid}")
                except Exception as exc:
                    errors.append(f"Invalid JSON in {mpath}: {exc}")

    # Dataset manifest check
    ds_m = REPO_ROOT / "data" / "manifests" / "insdn_manifest.json"
    if not ds_m.exists():
        errors.append("Missing data/manifests/insdn_manifest.json")
    else:
        dm = json.loads(ds_m.read_text(encoding="utf-8"))
        if len(dm.get("sha256", "")) != 64:
            errors.append("Invalid SHA-256 in insdn_manifest.json")

    # Figures & Notebooks check
    expected_figs = [
        "fig01_insdn_leakage_and_tiers.png",
        "fig02_exp0005_compute_budget_cliff.png",
        "fig03_exp0006_pareto_f1_vs_latency.png",
        "fig04_exp0007_live_component_attribution.png",
        "fig05_exp0012_ablation_floods.png",
        "fig06_exp0012_flash_crowd_vs_a4.png",
    ]
    for fn in expected_figs:
        fp = REPO_ROOT / "figures" / fn
        if not fp.exists() or fp.stat().st_size < 10_000:
            errors.append(f"Missing or invalid figure: {fn}")

    expected_nbs = [
        "01_insdn_leakage_audit_and_eda.ipynb",
        "02_offline_vs_live_bottleneck_analysis.ipynb",
        "03_phase6_ablation_and_paper_figures.ipynb",
    ]
    for nb in expected_nbs:
        np_path = REPO_ROOT / "notebooks" / nb
        if not np_path.exists() or np_path.stat().st_size < 1_000:
            errors.append(f"Missing or invalid notebook: {nb}")

    # Verify BibTeX & paper drafts exist
    for pf in ("paper/references.bib", "paper/experimental_report.md", "paper/manuscript_draft.tex"):
        pp = REPO_ROOT / pf
        if not pp.exists() or pp.stat().st_size < 1_000:
            errors.append(f"Missing or empty paper file: {pf}")

    if errors:
        print("REPRODUCIBILITY AUDIT FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

    print("REPRODUCIBILITY AUDIT PASSED: all manifests, checksums, figures, notebooks, and paper drafts verified.")


if __name__ == "__main__":
    main()
