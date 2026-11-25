# Research Question & Scope Definition

**Last Updated:** 2026-11-26  
**Source Proposal:** `presentations_and_ideas/2026-11-25_simplified_bachelors/KU_DSAI_Simplified_Pitch_2026-11-25.pptx`

## 1. Primary Research Gap

Offline AI intrusion detection accuracy (commonly >99% on static flow-level CSV datasets such as `InSDN` and `CIC-DDoS2019`) does not reliably predict real-time operational performance when deployed inside a live Software-Defined Networking (SDN) controller.

Under high-rate traffic or spoofed-header DDoS floods, executing flow feature extraction and AI inference inside the SDN control plane may induce:
- Elevated `Packet-In` processing tail latency (p95 / p99).
- High controller CPU utilization and cooperative event-loop blocking.
- Control-plane queue buildup and dropped/delayed `Packet-In` events.
- Degraded legitimate user throughput and elevated benign RTT / packet loss.
- Rapid switch flow-table occupancy growth toward configured capacity limits.

## 2. Central Research Question

> **RQ:** How can we design and evaluate a lightweight AI-based SDN intrusion detection and mitigation system that maintains strong detection performance while minimizing live controller overhead under realistic traffic conditions?

### Sub-Questions

- **RQ1 (Empirical Bottleneck Localization):** In a live SDN control plane (`Mininet` + `Open vSwitch` + `os-ken`), what is the dominant source of degradation under increasing `Packet-In` rates — base OpenFlow handling, switch flow-table insertion, live feature extraction, model inference, or Python event-loop/GIL blocking?
- **RQ2 (Offline vs. Live Divergence):** How strongly do standard offline ML/DL baselines (`Logistic Regression`, `Random Forest`, `XGBoost`/`LightGBM`, `MLP`, and heavier sequential/graph models only if justified) diverge when evaluated on live system cost (tail latency, CPU %, flow-table occupancy, benign QoS) versus offline classification metrics (Macro F1, FPR)?
- **RQ3 (Targeted Architectural Mitigation):** Given the empirically identified bottleneck, which architectural intervention (e.g., native OpenFlow lightweight features, asynchronous/decoupled inference, batching, selective/two-stage filtering, or early rate/entropy gating) achieves a statistically significant improvement in the detection-vs-overhead Pareto frontier?

## 3. Locked Research Scope (`DEC-006`)

Scope is formally locked to **Pure Live SDN Controller Bottleneck & Lightweight AI Defense** (Option B from the 2026-11-25 pitch proposal). Protocol-constrained adversarial evasion is intentionally deferred to future work so the 12-week 2-person project achieves rigorous systems-level depth, component attribution, multi-seed statistical validation, and native-Linux replication.
