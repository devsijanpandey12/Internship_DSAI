# Literature Review Tracker (Phase 2 — Verification Pending)

> **Scientific Integrity Policy:** Entries copied from the initial pitch deck are marked `NEEDS_DOI_VERIFICATION` until each paper's exact bibliographic details, DOI, experimental setup, and limitations are independently verified from primary peer-reviewed sources (IEEE Xplore, ACM DL, Springer, arXiv) during Phase 2. No unverified citation will enter the manuscript.

## Seed Papers Identified in Pitch Proposal

| # | Citation (From Proposal) | Area | Claimed Method / Focus | Claimed Limitation Relevant to Us | Verification Status |
| :---: | :--- | :--- | :--- | :--- | :---: |
| 1 | Elsayed et al., *IEEE Access*, 2020 — "InSDN: A Novel SDN Intrusion Dataset" | SDN Benchmark Dataset | Created SDN-specific intrusion dataset in Mininet/OVS/ONOS | Offline CSV only; no live controller CPU/latency profiling; known identifier leakage risk if IP/FlowID/Timestamp retained | `NEEDS_DOI_VERIFICATION` |
| 2 | Janabi et al., *IEEE Access*, 2024 — SDN-IDS Survey | SDN + AI Survey | Survey of ML/DL IDS in SDN | Highlights live controller bottleneck and flow-table exhaustion as open challenges | `NEEDS_DOI_VERIFICATION` |
| 3 | Dadhania et al., 2024–2025 — GNN-based SDN Anomaly Detection | GNN for SDN | GraphSAGE-based anomaly detection for high-speed SDN | High graph construction / inference cost on CPU controller | `NEEDS_DOI_VERIFICATION` |
| 4 | QoSentry, *JNSM*, 2025 | RL for SDN DDoS + QoS | RL-based QoS-preserving DDoS mitigation in Mininet | Evaluates QoS but heavy policy/controller overhead & scope comparison needed | `NEEDS_DOI_VERIFICATION` |
| 5 | He, Kim & Asghar, *IEEE COMST*, 2023 | Adversarial NIDS Survey | Survey of evasion/poisoning against ML-based NIDS | Notes many works violate network protocol constraints (relevant if Option A retained) | `NEEDS_DOI_VERIFICATION` |

## Phase 2 Targeted Literature Gaps to Search Next
1. Empirical SDN controller bottleneck & `Packet-In` latency / queuing studies (`Ryu` / `os-ken` / `ONOS` / `Floodlight` under synthetic floods, e.g., Cbench / Mininet).
2. Live feature-extraction overhead in OpenFlow controllers (native `OFPFlowStats` vs. `CICFlowMeter` / per-packet inspection).
3. Lightweight / two-stage / asynchronous / batched AI inference architectures inside SDN controllers.
4. Flow-table exhaustion / mitigation strategies (reactive vs. proactive, entropy/sketch gating, rule aggregation, timeout tuning).
