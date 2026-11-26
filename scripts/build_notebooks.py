"""Generate clean, reproducible EDA and results-analysis Jupyter notebooks under notebooks/."""

from __future__ import annotations

from pathlib import Path
import nbformat as nbf

REPO_ROOT = Path(__file__).resolve().parents[1]
NOTEBOOKS_DIR = REPO_ROOT / "notebooks"


def _md(text: str) -> nbf.NotebookNode:
    return nbf.v4.new_markdown_cell(text.strip() + "\n")


def _code(text: str) -> nbf.NotebookNode:
    return nbf.v4.new_code_cell(text.strip() + "\n")


def build_nb01_insdn_audit() -> Path:
    nb = nbf.v4.new_notebook()
    nb.cells = [
        _md(
            """
# 01 — InSDN Dataset Leakage Audit, Deduplication & SDN Observability Tiers

**Project:** Live SDN Controller Bottleneck & Lightweight AI Defense (KU DSAI Lab)  
**Design Policy (`DEC-009`):** Core data-loading and auditing logic lives in tested `.py` modules (`src/data/insdn_loader.py`); this notebook provides interactive visual inspection and exports `figures/fig01_insdn_leakage_and_tiers.png` directly from saved manifest/data files.
            """
        ),
        _code(
            """
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

REPO_ROOT = Path.cwd().resolve()
if REPO_ROOT.name == "notebooks":
    REPO_ROOT = REPO_ROOT.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from data.insdn_loader import load_clean_insdn

sns.set_theme(style="whitegrid", context="notebook")
FIG_DIR = REPO_ROOT / "figures"
FIG_DIR.mkdir(parents=True, exist_ok=True)

manifest = json.loads((REPO_ROOT / "data" / "manifests" / "insdn_manifest.json").read_text(encoding="utf-8"))
audit = manifest["audit"]
print(f"Dataset: {manifest['dataset_name']} | SHA-256: {manifest['sha256'][:16]}... | Rows: {audit['n_rows']:,} | Cols: {audit['n_columns']}")
            """
        ),
        _md(
            """
## 1. Automated Leakage & Data-Quality Audit Summary
Verify four classic sources of inflated offline accuracy in `InSDN` (mirroring findings by Engelen et al. 2021 & Lanvin et al. 2023):
1. **Exact & Feature-Only Duplicates:** Identical feature rows shared across train/test splits if not deduplicated first.
2. **IP Shortcut Leakage:** Attack traffic originating from IPs that never appear in benign captures.
3. **Destination Port Concentration:** Lab service-port bias (`53/443` benign vs `0/80` attack).
4. **Dead Zero-Variance Features:** Columns carrying zero information.
            """
        ),
        _code(
            """
audit_table = pd.DataFrame([
    {"Check": "Total raw rows", "Value": f"{audit['n_rows']:,}"},
    {"Check": "Normal / Attack raw split", "Value": f"{audit['binary_distribution']['Normal']:,} / {audit['binary_distribution']['Attack']:,}"},
    {"Check": "Feature-only duplicates (no IDs)", "Value": f"{audit['feature_only_duplicates_no_id']:,} ({100*audit['feature_only_duplicates_no_id']/audit['n_rows']:.2f}%)"},
    {"Check": "Zero-variance numeric columns", "Value": str(len(audit['zero_variance_columns']))},
    {"Check": "Attack rows from attack-only Src IP", "Value": f"{audit['ip_shortcut_leakage_audit']['Src IP']['attack_rows_with_attack_only_ip_pct']:.2f}%"},
    {"Check": "Attack rows targeting attack-only Dst IP", "Value": f"{audit['ip_shortcut_leakage_audit']['Dst IP']['attack_rows_with_attack_only_ip_pct']:.2f}%"},
    {"Check": "Clean non-constant numeric features (no Dst Port)", "Value": str(audit['observability_tiers']['T3_clean_numeric_count'])},
])
audit_table
            """
        ),
        _md(
            """
## 2. Visualize Dataset Deduplication, Port Bias & SDN Observability Tiers
            """
        ),
        _code(
            """
X_clean, y_bin, _, tiers = load_clean_insdn(
    REPO_ROOT / "data" / "raw" / "insdn" / "Dataset.csv",
    include_dst_port=False,
    deduplicate_features=True,
)
print(f"After leakage removal & feature deduplication: {len(X_clean):,} unique rows x {X_clean.shape[1]} features")
print(f"  Normal: {(y_bin == 0).sum():,} ({100*(y_bin == 0).mean():.1f}%) | Attack: {(y_bin == 1).sum():,} ({100*(y_bin == 1).mean():.1f}%)")

fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))

# Panel A: Raw vs Deduplicated class counts
raw_norm = audit["binary_distribution"]["Normal"]
raw_atk = audit["binary_distribution"]["Attack"]
dedup_norm = int((y_bin == 0).sum())
dedup_atk = int((y_bin == 1).sum())
x = np.arange(2)
w = 0.35
axes[0].bar(x - w/2, [raw_norm/1e3, raw_atk/1e3], width=w, label="Raw (343.9k)", color="#64748b")
axes[0].bar(x + w/2, [dedup_norm/1e3, dedup_atk/1e3], width=w, label=f"Deduplicated ({len(X_clean)/1e3:.1f}k)", color="#0284c7")
axes[0].set_xticks(x)
axes[0].set_xticklabels(["Normal", "Attack"])
axes[0].set_ylabel("Flow Count (Thousands)")
axes[0].set_title("(a) Feature-Duplicate Inflation in InSDN")
axes[0].legend()

# Panel B: Top Dst Port shortcut concentration
norm_ports = audit["dst_port_audit"]["top5_normal_dst_ports"]
atk_ports = audit["dst_port_audit"]["top5_attack_dst_ports"]
ports = ["0", "53", "80", "443"]
norm_vals = [100 * norm_ports.get(p, 0) / raw_norm for p in ports]
atk_vals = [100 * atk_ports.get(p, 0) / raw_atk for p in ports]
xp = np.arange(len(ports))
axes[1].bar(xp - w/2, norm_vals, width=w, label="Normal %", color="#16a34a")
axes[1].bar(xp + w/2, atk_vals, width=w, label="Attack %", color="#dc2626")
axes[1].set_xticks(xp)
axes[1].set_xticklabels([f"Port {p}" for p in ports])
axes[1].set_ylabel("Share of Class Flows (%)")
axes[1].set_title("(b) Lab Dst-Port Shortcut Bias")
axes[1].legend()

# Panel C: Feature count per SDN observability tier
tier_names = ["T1a\\nUnidir OF", "T1b\\nBidir OF", "T2\\nHdr+Flags", "T3\\nFull CIC"]
tier_counts = [len(tiers[k]) for k in ["T1a_Unidirectional_OF", "T1b_Bidirectional_OF", "T2_Header_Flags", "T3_Full_CICFlowMeter"]]
bars = axes[2].bar(tier_names, tier_counts, color=["#0ea5e9", "#2563eb", "#7c3aed", "#be123c"])
for b, c in zip(bars, tier_counts):
    axes[2].text(b.get_x() + b.get_width()/2, c + 1.5, str(c), ha="center", va="bottom", fontweight="bold")
axes[2].set_ylabel("Feature Count")
axes[2].set_ylim(0, max(tier_counts) + 12)
axes[2].set_title("(c) Features by SDN Observability Tier")

plt.tight_layout()
out_fig = FIG_DIR / "fig01_insdn_leakage_and_tiers.png"
plt.savefig(out_fig, dpi=220, bbox_inches="tight")
print(f"Saved figure -> {out_fig}")
plt.show()
            """
        ),
        _md(
            """
## 3. Exact Feature Lists per SDN Observability Tier
            """
        ),
        _code(
            """
for tname, cols in tiers.items():
    print(f"=== {tname} ({len(cols)} features) ===")
    print(", ".join(cols))
    print()
            """
        ),
    ]
    out_path = NOTEBOOKS_DIR / "01_insdn_leakage_audit_and_eda.ipynb"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    nbf.write(nb, out_path)
    return out_path


def build_nb02_offline_vs_live() -> Path:
    nb = nbf.v4.new_notebook()
    nb.cells = [
        _md(
            """
# 02 — Offline Accuracy vs. Live SDN Controller Compute Budget (`EXP-0002`, `EXP-0005`, `EXP-0006`)

**Data Integrity Rule:** Every table and figure below is generated programmatically from immutable saved CSVs under `experiments/results/`. No numbers are hardcoded or manually edited.
            """
        ),
        _code(
            """
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

REPO_ROOT = Path.cwd().resolve()
if REPO_ROOT.name == "notebooks":
    REPO_ROOT = REPO_ROOT.parent

sns.set_theme(style="whitegrid", context="notebook")
FIG_DIR = REPO_ROOT / "figures"
FIG_DIR.mkdir(parents=True, exist_ok=True)

df_exp2 = pd.read_csv(REPO_ROOT / "experiments" / "results" / "EXP-0002" / "phase_summary.csv")
df_exp5 = pd.read_csv(REPO_ROOT / "experiments" / "results" / "EXP-0005" / "aggregated_summary.csv")
df_exp6 = pd.read_csv(REPO_ROOT / "experiments" / "results" / "EXP-0006" / "offline_benchmark_summary.csv")
exp6_detail = json.loads((REPO_ROOT / "experiments" / "results" / "EXP-0006" / "detailed_results.json").read_text(encoding="utf-8"))

print(f"Loaded EXP-0002 ({len(df_exp2)} load phases), EXP-0005 ({len(df_exp5)} budget levels, N=3), EXP-0006 ({len(df_exp6)} tier x model configs)")
            """
        ),
        _md(
            """
## 1. Live SDN Controller Saturation Curve (`EXP-0005`, Core-Pinned, $N=3$ Seeds, 95% CI)
At a modest `250 pps` spoofed table-miss flood (`~500 Packet-In/s` across `s1+s2`, zero flow-table refusals), synchronous CPU work per `Packet-In` hits a hard saturation cliff between **`1.0 ms`** and **`2.0 ms`**.
            """
        ),
        _code(
            """
display_cols = [
    "inject_cpu_ms", "controller_packet_in_pps_mean", "controller_cpu_mean_pct_mean",
    "event_loop_lag_p95_ms_mean", "benign_new_flow_success_pct_mean", "benign_new_flow_p95_ms_mean"
]
df_exp5[display_cols]
            """
        ),
        _code(
            """
fig, axes = plt.subplots(1, 2, figsize=(13.5, 4.8))

x = df_exp5["inject_cpu_ms"]

# Panel A: Controller CPU & Event-loop lag p95
ax1 = axes[0]
ax1.errorbar(
    x, df_exp5["controller_cpu_mean_pct_mean"], yerr=df_exp5["controller_cpu_mean_pct_ci95"],
    marker="o", linewidth=2, capsize=4, color="#2563eb", label="Controller CPU Mean (%)"
)
ax1.axvspan(1.0, 2.0, color="#fef08a", alpha=0.35, label="Saturation Cliff (1.0–2.0 ms)")
ax1.set_xlabel("Injected Synchronous Compute per Packet-In (ms)")
ax1.set_ylabel("Controller CPU (% of 1 Pinned Core)", color="#2563eb")
ax1.set_ylim(0, 112)
ax1.set_title("(a) Core-Pinned os-ken CPU & Event-Loop Starvation (250 pps, N=3)")

ax1b = ax1.twinx()
ax1b.errorbar(
    x, df_exp5["event_loop_lag_p95_ms_mean"], yerr=df_exp5["event_loop_lag_p95_ms_ci95"],
    marker="s", linestyle="--", linewidth=2, capsize=4, color="#dc2626", label="Event-Loop Lag p95 (ms)"
)
ax1b.set_ylabel("Event-Loop Heartbeat Lag p95 (ms)", color="#dc2626")

h1, l1 = ax1.get_legend_handles_labels()
h2, l2 = ax1b.get_legend_handles_labels()
ax1.legend(h1 + h2, l1 + l2, loc="lower right", fontsize=8.5, framealpha=0.95)

# Panel B: Processed Packet-In rate & Legitimate New-TCP Setup Success Rate
ax2 = axes[1]
ax2.errorbar(
    x, df_exp5["benign_new_flow_success_pct_mean"], yerr=df_exp5["benign_new_flow_success_pct_ci95"],
    marker="D", linewidth=2.2, capsize=4, color="#16a34a", label="Benign New-TCP Setup Success (%)"
)
ax2.axvspan(1.0, 2.0, color="#fef08a", alpha=0.35)
ax2.set_xlabel("Injected Synchronous Compute per Packet-In (ms)")
ax2.set_ylabel("Legitimate New-TCP Setup Success (%)", color="#16a34a")
ax2.set_ylim(0, 112)
ax2.set_title("(b) Legitimate New-Flow Collapse & Control-Plane Throughput Drop")

ax2b = ax2.twinx()
ax2b.errorbar(
    x, df_exp5["controller_packet_in_pps_mean"], yerr=df_exp5["controller_packet_in_pps_ci95"],
    marker="^", linestyle="--", linewidth=2, capsize=4, color="#7c3aed", label="Processed Packet-In/s"
)
ax2b.set_ylabel("Controller Processed Packet-In/s", color="#7c3aed")
ax2b.set_ylim(0, 560)

h3, l3 = ax2.get_legend_handles_labels()
h4, l4 = ax2b.get_legend_handles_labels()
ax2.legend(h3 + h4, l3 + l4, loc="lower left", fontsize=8.5)

plt.tight_layout()
out_fig = FIG_DIR / "fig02_exp0005_compute_budget_cliff.png"
plt.savefig(out_fig, dpi=220, bbox_inches="tight")
print(f"Saved figure -> {out_fig}")
plt.show()
            """
        ),
        _md(
            """
## 2. Offline Leakage-Free `InSDN` Quality vs. Reactive Single-Sample (`batch=1`) CPU Latency (`EXP-0006`)
Overlay every trained model's single-sample (`batch=1`) p95 CPU inference latency directly against **`EXP-0005`'s `1.0 ms` synchronous budget ceiling**, and quantify the speedup unlocked by micro-batching (`batch=64`).
            """
        ),
        _code(
            """
df_exp6[[
    "tier", "n_features", "model", "test_macro_f1", "test_fpr",
    "batch1_p50_ms", "batch1_p95_ms", "batch64_per_flow_p50_ms",
    "batching_speedup_x", "exceeds_exp0005_1ms_p95"
]].sort_values(["tier", "batch1_p95_ms"])
            """
        ),
        _code(
            """
fig, axes = plt.subplots(1, 2, figsize=(14.5, 5.2))

tier_markers = {
    "T1a_Unidirectional_OF": "o",
    "T1b_Bidirectional_OF": "s",
    "T2_Header_Flags": "^",
    "T3_Full_CICFlowMeter": "D",
}
model_colors = {
    "logistic_regression": "#0284c7",
    "lightgbm": "#16a34a",
    "xgboost": "#ea580c",
    "random_forest": "#dc2626",
    "mlp": "#7c3aed",
}

# Panel A: Macro F1 vs batch=1 p95 latency (log x-axis) with EXP-0005 1.0 ms wall
ax = axes[0]
for _, r in df_exp6.iterrows():
    ax.scatter(
        r["batch1_p95_ms"], r["test_macro_f1"],
        color=model_colors[r["model"]],
        marker=tier_markers[r["tier"]],
        s=95, edgecolor="black", linewidth=0.6, alpha=0.9
    )

ax.axvline(1.0, color="#dc2626", linestyle="--", linewidth=2, label="EXP-0005 Sync Budget (1.0 ms)")
ax.axvspan(1.0, max(df_exp6["batch1_p95_ms"].max() * 1.4, 20), color="#fee2e2", alpha=0.35, label="Controller Overload Zone")
ax.set_xscale("log")
ax.set_xlabel("Reactive Single-Sample (batch=1) Inference Latency p95 (ms, log scale)")
ax.set_ylabel("Leakage-Free Test Macro F1 (InSDN)")
ax.set_title("(a) Accuracy vs. Reactive Latency Against EXP-0005 Budget")

# Build clean dual legend (colors=model, shapes=tier)
from matplotlib.lines import Line2D
handles = [Line2D([0], [0], color="#dc2626", linestyle="--", lw=2, label="EXP-0005 1.0 ms Ceiling")]
for m, c in model_colors.items():
    handles.append(Line2D([0], [0], marker="o", color="w", markerfacecolor=c, markeredgecolor="k", markersize=8, label=m))
for t, mk in tier_markers.items():
    handles.append(Line2D([0], [0], marker=mk, color="w", markerfacecolor="#475569", markeredgecolor="k", markersize=8, label=t.split("_")[0]))
ax.legend(handles=handles, loc="lower right", fontsize=7.5, ncol=2, framealpha=0.95)

# Panel B: Batch=1 vs Batch=64 per-flow latency for T1b_Bidirectional_OF
sub = df_exp6[df_exp6["tier"] == "T1b_Bidirectional_OF"].sort_values("batch1_p50_ms")
y_pos = np.arange(len(sub))
h = 0.36
axes[1].barh(y_pos - h/2, sub["batch1_p50_ms"], height=h, color="#ef4444", label="Reactive batch=1 (p50 ms/flow)")
axes[1].barh(y_pos + h/2, sub["batch64_per_flow_p50_ms"], height=h, color="#0ea5e9", label="Micro-batch=64 (p50 ms/flow)")
axes[1].set_xscale("log")
axes[1].set_xlim(right=45)
axes[1].set_yticks(y_pos)
axes[1].set_yticklabels(sub["model"])
axes[1].set_xlabel("Per-Flow CPU Inference Latency (ms, log scale)")
axes[1].set_title("(b) Micro-Batching Speedup (T1b Bidirectional OpenFlow Tier)")
for idx, (_, r) in enumerate(sub.iterrows()):
    axes[1].text(
        r["batch1_p50_ms"] * 1.15, idx - h/2,
        f"{r['batching_speedup_x']:.1f}x faster", va="center", fontsize=8.5, fontweight="bold"
    )
axes[1].legend(loc="lower right", fontsize=8.5, framealpha=0.95)

plt.tight_layout()
out_fig = FIG_DIR / "fig03_exp0006_pareto_f1_vs_latency.png"
plt.savefig(out_fig, dpi=220, bbox_inches="tight")
print(f"Saved figure -> {out_fig}")
plt.show()
            """
        ),
        _md(
            """
## 3. Destination-Port Shortcut Leakage Ablation
Quantifies how much adding `Dst Port` inflates simple linear/tree models on `InSDN` due to lab port bias (`53/443` vs `0/80`).
            """
        ),
        _code(
            """
ab_df = pd.DataFrame(exp6_detail.get("dst_port_ablation", []))
base_t1a = df_exp6[(df_exp6["tier"] == "T1a_Unidirectional_OF") & (df_exp6["model"].isin(["logistic_regression", "lightgbm"]))][["tier", "model", "n_features", "test_macro_f1", "test_fpr"]]
pd.concat([base_t1a, ab_df], ignore_index=True)
            """
        ),
        _md(
            """
## 4. Live SDN Component Attribution (`EXP-0007`, Core-Pinned `os-ken`, 250 pps, $N=3$ Seeds)
Direct microsecond breakdown of live `Packet-In` handling (`base_ofp` vs. `feature_extract` vs. `model_infer`) paired with Controller CPU % and Legitimate New-TCP Setup Success %.
            """
        ),
        _code(
            """
df_exp7 = pd.read_csv(REPO_ROOT / "experiments" / "results" / "EXP-0007" / "aggregated_summary.csv")
df_exp7[[
    "pipeline", "offline_test_macro_f1", "base_ofp_p50_ms_mean",
    "feature_extract_p50_ms_mean", "model_infer_p50_ms_mean",
    "event_loop_lag_p95_ms_mean", "controller_cpu_mean_pct_mean",
    "benign_new_flow_success_pct_mean"
]]
            """
        ),
        _code(
            """
fig, axes = plt.subplots(1, 2, figsize=(15, 5.2))

short_labels = [
    "NoAI\\n(Base A)", "Feats\\nT1a", "Feats\\nT3 CIC",
    "T1a+LR\\n(Base B)", "T1a+LGBM\\n(Base B)", "T1a+XGB\\n(Base B)",
    "T1a+RF\\n(Base C)", "T3+RF\\n(Base C)"
]
x = np.arange(len(df_exp7))

# Panel A: Stacked component latency breakdown (p50 ms)
base_v = df_exp7["base_ofp_p50_ms_mean"].to_numpy()
feat_v = df_exp7["feature_extract_p50_ms_mean"].to_numpy()
inf_v = df_exp7["model_infer_p50_ms_mean"].to_numpy()

axes[0].bar(x, base_v, label="Base OpenFlow + Parsing", color="#64748b")
axes[0].bar(x, feat_v, bottom=base_v, label="Live Feature Extraction", color="#f59e0b")
axes[0].bar(x, inf_v, bottom=base_v + feat_v, label="Sync ML Inference (batch=1)", color="#dc2626")
axes[0].axhline(1.0, color="#111827", linestyle="--", linewidth=1.6, label="EXP-0005 ~1.0 ms Sync Budget")
axes[0].set_xticks(x)
axes[0].set_xticklabels(short_labels, fontsize=8.5)
axes[0].set_ylabel("Median Per-Packet-In Latency (ms)")
axes[0].set_title("(a) Live os-ken Component Latency Breakdown (250 pps, N=3)")
axes[0].legend(loc="upper left", fontsize=8.5, framealpha=0.95)

# Panel B: Controller CPU (%) & Benign New-TCP Setup Success (%)
w = 0.38
axes[1].bar(
    x - w/2, df_exp7["controller_cpu_mean_pct_mean"], width=w,
    yerr=df_exp7["controller_cpu_mean_pct_ci95"], capsize=3,
    color="#2563eb", label="Controller CPU Mean (%)"
)
axes[1].bar(
    x + w/2, df_exp7["benign_new_flow_success_pct_mean"], width=w,
    yerr=df_exp7["benign_new_flow_success_pct_ci95"], capsize=3,
    color="#16a34a", label="Benign New-TCP Setup OK (%)"
)
axes[1].set_xticks(x)
axes[1].set_xticklabels(short_labels, fontsize=8.5)
axes[1].set_ylabel("Percentage (%)")
axes[1].set_ylim(0, 118)
axes[1].set_title("(b) Live Controller CPU vs. Legitimate New-Flow Survival (95% CI)")
axes[1].legend(loc="upper center", ncol=2, fontsize=8.5, framealpha=0.95)

plt.tight_layout()
out_fig = FIG_DIR / "fig04_exp0007_live_component_attribution.png"
plt.savefig(out_fig, dpi=220, bbox_inches="tight")
print(f"Saved figure -> {out_fig}")
plt.show()
            """
        ),
    ]
    out_path = NOTEBOOKS_DIR / "02_offline_vs_live_bottleneck_analysis.ipynb"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    nbf.write(nb, out_path)
    return out_path


def main() -> None:
    p1 = build_nb01_insdn_audit()
    p2 = build_nb02_offline_vs_live()
    print(f"Generated notebooks:\n  - {p1}\n  - {p2}")


if __name__ == "__main__":
    main()
