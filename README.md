# Live SDN Controller Bottleneck & Lightweight AI Defense

**Institution:** Kathmandu University, Department of Artificial Intelligence — DSAI Lab  
**Supervisor:** Dr. Manoj Shakya, PhD  
**Timeline:** 12-Week Research Internship (17 Nov 2026 – 16 Feb 2027)  

## Research Gap

Offline AI intrusion detection accuracy (often >99% on static flow CSVs such as `InSDN` and `CIC-DDoS2019`) does not translate directly into efficient real-time deployment inside a live Software-Defined Networking (SDN) controller. Under high-rate traffic or spoofed DDoS floods, live feature extraction, model inference, and synchronous controller execution can saturate CPU, inflate `Packet-In` tail latency (p95/p99), exhaust switch flow tables, and degrade legitimate user QoS.

## Repository Structure

```text
research/
├── README.md                  # Project overview & quickstart
├── pyproject.toml             # Reproducible Python dependency manifest
├── configs/                   # YAML experiment configurations (no hardcoded params)
├── docker/                    # Isolated Linux/Mininet/OVS/os-ken container setup
├── docs/                      # Living research docs (RQ, hypotheses, protocol, decisions, lit review)
├── data/
│   ├── raw/                   # Unmodified external datasets (gitignored; tracked via manifests/)
│   ├── processed/             # Cleaned, leakage-free splits (gitignored; tracked via manifests/)
│   └── manifests/             # Dataset versions, SHA-256 checksums, cleaning rules
├── src/
│   ├── data/                  # Dataset loaders, leakage audits, splitting
│   ├── features/              # Native OpenFlow vs. flow-stat feature extractors
│   ├── models/                # Baseline and lightweight ML/DL models
│   ├── controller/            # os-ken OpenFlow 1.3 controllers + telemetry instrumentation
│   ├── mitigation/            # Flow-rule mitigation, rate limiting, staged defenses
│   └── evaluation/            # Experiment runner, metrics aggregation, statistical tests
├── topology/                  # Mininet topologies (minimal baseline -> multi-switch/DPI)
├── scripts/                   # Experiment entrypoints and reproduction helpers
├── tests/                     # Unit & integration tests for instrumentation and pipelines
├── experiments/
│   ├── registry.csv           # Master append-only log of all experiments (successes & failures)
│   ├── manifests/             # Full JSON metadata snapshot per experiment ID
│   ├── results/               # Structured raw & aggregated CSV/JSON metrics (never overwritten)
│   ├── logs/                  # Controller, switch, and runner logs per experiment ID
│   └── artifacts/             # Saved models, profiles, intermediate traces
├── notebooks/                 # Exploratory analysis notebooks (read-only over experiments/results/)
├── figures/                   # Paper-ready figures generated strictly from saved results
└── paper/                     # LaTeX manuscript drafts, tables, bibliography
```

## Core Principles

1. **Measure before assuming:** Isolate base controller/switch overhead (Baseline A) before adding feature extraction or AI models.
2. **Never overwrite results:** Every run gets an immutable Experiment ID (`EXP-0001`–`EXP-0012`) with manifest, git commit hash, seed, environment snapshot, and raw metrics.
3. **Preserve negative results:** Failed, invalid, and interrupted runs (`EXP-0001`, `0003`, `0004`, `0009`, `0010`, `0011`) are archived and root-caused, never deleted.
4. **Honest instrumentation:** In Open vSwitch software switches, flow-table occupancy is reported as a configured software flow-table capacity proxy (`flow_limit`), never misrepresented as physical hardware TCAM.

## Key Deliverables & Reproduction

- **Paper-Ready Experimental Report:** `paper/experimental_report.md`
- **IEEE Conference Manuscript Draft & Verified BibTeX:** `paper/manuscript_draft.tex`, `paper/references.bib` (16 verified studies / 18 BibTeX entries with DOIs)
- **Executed Analysis Notebooks:** `notebooks/01_insdn_leakage_audit_and_eda.ipynb`, `notebooks/02_offline_vs_live_bottleneck_analysis.ipynb`, `notebooks/03_phase6_ablation_and_paper_figures.ipynb`
- **Paper Figures (Generated Strictly from Saved CSVs/JSONs):** `figures/fig01`–`figures/fig06`
- **Quick Verification:**
  ```bash
  pytest -v tests/
  python scripts/verify_reproducibility.py
  ```
