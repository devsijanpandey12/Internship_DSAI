# Closing the Offline-to-Live Gap in AI-Based SDN Intrusion Detection: Empirical Bottleneck Attribution and a Two-Stage Decoupled Defense

**Type:** Paper-Ready Experimental Research Report (Phases 1–8)  
**Institution:** Kathmandu University, Department of Artificial Intelligence — DSAI Lab  
**Authors:** Sijan Panday and DSAI Lab Research Partner  
**Supervisor:** Dr. Manoj Shakya, PhD  
**Timeline:** 12-Week Research Internship (`17 Nov 2026 – 16 Feb 2027`)  
**Scope Lock:** Pure Live SDN Controller Bottleneck & Lightweight AI Defense (`DEC-006`)  
**Repository:** `c:/Users/sijan/Desktop/intern/research` (`https://github.com/devsijanpandey12/Internship_DSAI.git`)

---

## Abstract

Machine learning and deep learning intrusion detection systems (IDS) for Software-Defined Networking (SDN) routinely report >99% offline F1 scores on static flow-level benchmarks such as `InSDN`. However, offline accuracy does not reliably translate into real-time operational viability when deployed inside a live OpenFlow controller under volumetric or spoofed-header DDoS floods. In this study, we construct an isolated, core-pinned, reproducible Mininet + Open vSwitch 2.17 + `os-ken` OpenFlow 1.3 testbed and conduct twelve logged experiments (`EXP-0001`–`EXP-0012`) to (i) audit shortcut leakage in `InSDN`, (ii) quantify the controller's exact synchronous compute budget, (iii) attribute live control-plane collapse across base OpenFlow processing, live feature extraction, synchronous `batch=1` model inference, and cooperative `eventlet` loop starvation, and (iv) design and statistically evaluate a targeted defense.

Our measurements overturn a common assumption in lightweight SDN-IDS literature: inside a live reactive Python OpenFlow controller, **synchronous `batch=1` inference dispatch — not feature extraction — dominates per-`Packet-In` latency**. For a `RandomForest` classifier achieving `0.9998` offline Macro F1 on 65 `CICFlowMeter`-style features (`T3`), `85.2%` of live handler time (`3.12 ms` of `3.66 ms`) is spent in inference versus `4.7%` (`0.17 ms`) in 65-feature extraction; live deployment at only `250 pps` spoofed table-miss traffic saturates controller CPU (`98.3%`), inflates `eventlet` loop lag `29x` (`1.02 -> 29.46 ms`), collapses legitimate new-TCP setup to `16.7%`, and flags only `0.03%` (`1` of `2,684–3,225`) of live spoofed floods due to single-packet `Packet-In` observability blindness. Even lightweight `LightGBM` on 6 OpenFlow-native features (`T1a`) saturates controller CPU (`96.8–97.5%`) and inflates legitimate new-TCP setup p95 latency by `78x–108x` (`1,102–1,794 ms`) at `800 pps`.

Guided directly by these empirical mechanisms, we build and ablate a **Two-Stage Decoupled Defense (`A3`)** combining (1) an O(1) Stage-1 port-rate gatekeeper and Selective Flow-Table Guard on the `Packet-In` hot path with (2) an out-of-process, core-pinned Stage-2 LightGBM classifier operating over 10 IP/port-agnostic 250 ms OpenFlow window features via eventlet-safe `multiprocessing.Pipe` IPC. Across `N=5` unseen random seeds (`75/75` core-pinned trials in `EXP-0012`), `A3` reduces controller CPU under `800 pps` UDP and TCP SYN floods from `97.5%` / `96.8%` (`A1` synchronous LightGBM) to `5.1%` / `4.4%` ($p = 0.0119$, Mann-Whitney U; Stage-2 worker CPU $\le 0.34\%$), reduces peak `s1` software flow-table occupancy by `11.1x–12.1x` relative to unguarded asynchronous ML (`A2`: `16.32–17.38%` -> `A3`: `1.44–1.47%`, $p \le 0.0097$, `0` `TABLE_FULL` refusals), and maintains `100.0%` benign new-TCP completion (`14.1–16.6 ms` p95). Crucially, under a `60 conn/s` legitimate TCP flash crowd with zero attack traffic, a static rate threshold (`A4`) causes `4.0` false port blocks per run, collapsing legitimate completion to `61.0%` (`1,071 ms` p95), whereas `A3` preserves `100.0%` completion ($p = 0.0075$), `0.0` false mitigations ($p = 0.0040$), and `23.5%` controller CPU matching the no-AI baseline (`23.5%`). We conclude with an explicit analysis of testbed threats to validity (WSL2 userspace `netdev` OVS vs. native Linux kernel OVS + `TCLink`, software flow-table proxies vs. physical TCAM, and single-IP vs. distributed multi-IP flash crowds) and an honest publication-readiness roadmap.

---

## 1. Introduction

Software-Defined Networking (SDN) decouples the programmable control plane from the packet-forwarding data plane via Southbound APIs such as OpenFlow 1.3. While centralized visibility makes SDN an attractive platform for AI-based intrusion detection, reactive OpenFlow forwarding introduces a structural vulnerability: packets matching no installed flow rule generate `OFPPacketIn` messages sent from switches to the controller. Under spoofed-source-IP/port flooding, every arriving packet triggers a distinct table miss, stressing both the controller's event loop and the switch's flow-table capacity.

A large body of SDN-IDS research trains tree ensembles, multilayer perceptrons, CNNs, or GNNs on static flow-level CSV datasets (`InSDN`, `CIC-DDoS2019`, `CIC-IDS2017`) and reports offline F1 scores exceeding `99%`. Yet deploying an offline-validated classifier directly into a live controller faces three intertwined systems barriers that static evaluation hides:

1. **Observability Mismatch:** Offline datasets extracted post-hoc with `CICFlowMeter` contain 65–80+ bidirectional packet-size, inter-arrival-time (IAT), and TCP-window statistics computed over completed flows. At `Packet-In` #1 of a spoofed table-miss flood, however, a reactive controller sees only a single packet (`Tot Fwd Pkts = 1`, `Tot Bwd Pkts = 0`, `IAT = 0`).
2. **Synchronous Control-Plane Saturation:** Single-threaded Python controllers (e.g., `Ryu` and its maintained OpenStack fork `os-ken`) dispatch `Packet-In` events inside a cooperative `eventlet` greenlet loop bound by the Python GIL. Any synchronous per-event CPU work exceeding the inverse arrival rate starves heartbeat scheduling, queues `Packet-In` events, and delays legitimate new-flow `OFPFlowMod` installation.
3. **False-Blocking vs. Static-Threshold Trade-off:** Purely heuristic rate limiters react rapidly with negligible CPU cost, but cannot distinguish spoofed table-miss floods from legitimate high-rate TCP flash crowds, creating severe collateral denial of service.

This report documents a disciplined, end-to-end empirical investigation addressing the central research question:

> **RQ:** *How can we design and evaluate a lightweight AI-based SDN intrusion detection and mitigation system that maintains strong detection performance while minimizing live controller overhead under realistic traffic conditions?*

In contrast to demonstration-style SDN-ML prototypes, our methodology enforces five research engineering standards: (i) **measure before assuming** (Baseline A without AI before adding ML), (ii) **immutable experiment logging** (`EXP-0001`–`EXP-0012` with JSON manifests, Git hashes, seeds, and preserved failed runs), (iii) **distribution-level telemetry** (`p50/p95/p99` latencies rather than means alone), (iv) **honest metric naming** (explicitly distinguishing OVS `flow_limit` software capacity proxies from physical hardware TCAM), and (v) **single-variable controlled ablations** across `N=5` unseen seeds with nonparametric significance testing.

---

## 2. Related Work and Verified Literature Gap

We reviewed 16 peer-reviewed studies across IEEE, ACM, Springer, and Elsevier (complete verified bibliography in [references.bib](file:///c:/Users/sijan/Desktop/intern/research/paper/references.bib) and structured matrix in [literature_review.md](file:///c:/Users/sijan/Desktop/intern/research/docs/literature_review.md)), identifying a persistent disciplinary split between control-plane systems protection and AI-based SDN intrusion detection.

### 2.1 SDN Control-Plane Saturation & Flow-Table Protection

Early control-plane defenses focused on shielding OpenFlow controllers from data-to-control saturation without machine learning. **AVANT-GUARD** (Shin et al., ACM CCS 2013, DOI: `10.1145/2508859.2516684`) introduced switch-side TCP connection migration to block uncompleted SYN floods before `Packet-In` dispatch, but is restricted to TCP and requires switch data-plane modifications. **FloodGuard** (Wang et al., IEEE/IFIP DSN 2015, DOI: `10.1109/DSN.2015.39`) generalized protection to protocol-agnostic floods using proactive flow-rule analysis and data-plane packet-migration caching, while **FlowRanger** (Wei & Fung, IEEE ICC 2015, DOI: `10.1109/ICC.2015.7249114`) replaced drop-tail `Packet-In` queues with trust-weighted priority scheduling. Subsequent work targeted switch flow-table exhaustion specifically: **Xu et al.** (IEEE TNSM 2017, DOI: `10.1109/TNSM.2017.2758796`) proposed token-bucket mitigation for volumetric overflow, **Yu et al.** (IEEE/ACM ToN 2021, DOI: `10.1109/TNET.2021.3115161`) formalized adversarial flow-table probing, and **FTMaster** (Tang et al., IEEE TNSM 2023, DOI: `10.1109/TNSM.2023.3270339`) and **FloRa** (Mudgal et al., IEEE TNSM 2024, DOI: `10.1109/TNSM.2024.3446178`) addressed stealthy low-rate table overflow. None of these systems profile live ML feature-extraction or inference overhead inside the controller.

### 2.2 SDN-IDS Datasets, Shortcut Artifacts, and Offline-Only Models

Benchmark datasets such as **CIC-DDoS2019** (Sharafaldin et al., IEEE ICCST 2019, DOI: `10.1109/CCST.2019.8888419`) and **InSDN** (Elsayed et al., IEEE Access 2020, DOI: `10.1109/ACCESS.2020.3022633`) popularized 80+-feature `CICFlowMeter` CSV classification. However, independent dataset audits by **Engelen et al.** (IEEE S&PW 2021, DOI: `10.1109/SPW53761.2021.00009`), **Liu et al.** (IEEE CNS 2022, DOI: `10.1109/CNS56114.2022.9947235`), and **Lanvin et al.** (CRiSIS 2023, DOI: `10.1007/978-3-031-31108-6_2`) demonstrated widespread `CICFlowMeter` extraction defects, duplicate flows, and lab-environment shortcuts that inflate offline metrics to ~99.9% while failing in realistic operation. Recent architectures like **Dadhania et al.** (Cyber Security and Applications 2024, DOI: `10.1016/j.csa.2024.100079`) apply Graph Neural Networks strictly offline without live OpenFlow profiling. **Janabi et al.** (IEEE Access 2024, DOI: `10.1109/ACCESS.2024.3493384`) explicitly highlight live controller overhead, real-time feature extraction cost, and flow-table exhaustion as unresolved deployment gaps in their SDN-IDS survey.

### 2.3 Lightweight, Two-Stage, and QoS-Aware SDN Defenses

**LUCID** (Doriguzzi-Corin et al., IEEE TNSM 2020, DOI: `10.1109/TNSM.2020.2971776`) reduced deep-learning inference time using a lightweight 1D-CNN over fixed packet-header windows, but benchmarked offline replay outside an active OpenFlow event loop. **Liu et al.** (FGCS 2022, DOI: `10.1016/j.future.2021.11.009`) and **Hassan et al.** (Scientific Reports 2024, DOI: `10.1038/s41598-024-67984-w`) combined coarse entropy triggers with downstream ML/CNN stages in Mininet, reporting average detection latency rather than `p95/p99` handler latency, cooperative loop lag, component-level attribution, or benign flash-crowd false blocking. **QoSentry** (Khozam et al., JNSM 2025, DOI: `10.1007/s10922-025-09971-8`) underscored measuring live benign user QoS retention during mitigation using reinforcement learning, but did not decompose per-event feature-extraction vs. inference bottlenecks on the `Packet-In` hot path.

### 2.4 Synthesized Contribution

Our work bridges this gap by combining: (1) a leakage-and-observability audit of `InSDN` paired with a live microsecond component breakdown (`base OpenFlow` vs. `feature extraction` vs. `synchronous batch=1 inference` vs. `event-loop starvation`), and (2) a controlled, single-variable ablation (`A0`–`A4`) of a two-stage decoupled windowed architecture validated simultaneously on volumetric spoofed floods (UDP & TCP SYN) and benign high-rate TCP flash crowds.

---

## 3. Research Questions and Falsifiable Hypotheses

We operationalized our central research question into three sub-questions (**RQ1**: empirical bottleneck localization; **RQ2**: offline-vs-live divergence across observability tiers and model families; **RQ3**: single-variable architectural mitigation) and seven pre-registered, falsifiable hypotheses (tracked in [hypotheses.md](file:///c:/Users/sijan/Desktop/intern/research/docs/hypotheses.md)):

| ID | Statement Summary | Primary Evidence | Final Disposition |
| :--- | :--- | :--- | :---: |
| **H0** | Reactive `os-ken` without AI exhibits a nonlinear saturation knee under spoofed `Packet-In` sweeps. | `EXP-0002`: CPU `1.35 -> 96.98%`, loop lag `0.97 -> 7.01 ms`, new-TCP OK drops to `37.5%` at `1,500 pps`. | **SUPPORTED** *(WSL2 `netdev`)* |
| **H0b** | Core-pinned `os-ken` at `250 pps` (`~500 Packet-In/s`) exhibits a sharp synchronous compute cliff near `~1.5 ms`. | `EXP-0005` (`N=3`): `1.0 ms` (`78.9%` CPU, `100%` TCP OK) -> `2.0 ms` (`97.4%` CPU, `31.9 ms` lag, `47.6%` TCP OK). | **SUPPORTED** |
| **H1** | Synchronous `CICFlowMeter`-style feature extraction contributes equal or greater latency than lightweight inference. | `EXP-0007` (`N=3`): 65-feat `T3` extraction = `0.17 ms` (`4.7%`), while `batch=1` RF = `3.12 ms` (`85.2%`); `T1a` LGBM/XGB dispatch (`0.40–0.44 ms`) is `40x` larger than `T1a` extraction (`0.010 ms`). | **REFUTED / REFINED** |
| **H2** | Models with near-identical offline F1 diverge sharply (`>5x` tail latency/QoS) when deployed live. | `EXP-0006` + `EXP-0007`: `T3+RF` (`99.98%` offline F1) collapses live (`98.3%` CPU, `29.5 ms` lag, `16.7%` TCP OK, `0.03%` live detection) vs. `T1a+LGBM` (`49.6%` CPU, `100%` TCP OK at `250 pps`). | **SUPPORTED** |
| **H3a** | Decoupling windowed ML off `eventlet`/GIL (`A2`) cuts CPU `>50%`, lag `>5x`, and restores TCP OK `>=95%` at `800 pps` vs. sync ML (`A1`). | `EXP-0012` (`N=5`): UDP CPU `97.5 -> 5.6%`, lag `10.59 -> 0.93 ms`, TCP OK `80.0 -> 100.0%`; SYN CPU `96.8 -> 5.8%`, p95 `1,793.5 -> 11.3 ms`. | **SUPPORTED** |
| **H3b** | Adding Stage-1 O(1) gate + Selective Flow-Table Guard (`A3` vs. `A2`) cuts peak `s1` occupancy `>50%` with `0` `TABLE_FULL` and eliminates unnecessary IPC. | `EXP-0012` (`N=5`): `s1` occupancy drops `11.1x` on UDP (`16.32 -> 1.47%`, $p=0.0097$) & `12.1x` on SYN (`17.38 -> 1.44%`, $p=0.0075$); IPC drops `6.4x` (`27.0 -> 4.2`); `0` `TABLE_FULL`. | **SUPPORTED** |
| **H3c** | Under a `60 conn/s` legitimate TCP flash crowd, static rate limiting (`A4`) causes collateral blocking while `A3` preserves `>=95%` benign completion. | `EXP-0012` (`N=5`): `A4` drops completion to `61.0%` (`4.0` FP drops, `1,071 ms` p95); `A3` preserves `100.0%` ($p=0.0075$), `0.0` FP drops ($p=0.0040$), `15.6 ms` p95. | **SUPPORTED** |

---

## 4. Methodology and System Design

### 4.1 Isolated Live SDN Testbed and Core-Pinning Discipline

All live experiments execute inside an immutable Ubuntu 22.04 privileged Docker image (`ku-dsai-sdn:0.2`, defined in [Dockerfile.sdn](file:///c:/Users/sijan/Desktop/intern/research/docker/Dockerfile.sdn)) running Mininet `2.3.0`, Open vSwitch `2.17.12`, `os-ken 2.11.0`, `eventlet 0.35.2`, `iperf3`, `scapy 2.5.0`, `scikit-learn 1.5.2`, `lightgbm 4.5.0`, and `xgboost 2.1.1`. Because the host Windows 11 Home / WSL2 kernel (`5.15.153.1-microsoft-standard-WSL2` on an AMD Ryzen 7 7840HS, 8C/16T, 15.19 GB RAM) disables `CONFIG_OPENVSWITCH` and `sch_htb`/`sch_netem` (`DEC-004`), OVS runs in userspace `netdev` mode with `ethtool` `veth` TX/RX/TSO/GSO/GRO checksum offload disabled (`DEC-005`).

To eliminate host CPU contention between userspace `ovs-vswitchd`, the SDN controller, traffic generators, and the asynchronous ML worker, all Phase 3B–6 experiments enforce strict `taskset` CPU affinity (`DEC-006`):
- **Core 0:** `os-ken` OpenFlow 1.3 controller (single-threaded `eventlet` loop).
- **Core 1:** Attack and benign traffic generators.
- **Cores 2–7:** `ovs-vswitchd` data-plane threads.
- **Core 8:** Decoupled Stage-2 ML worker process (in `A2`/`A3`).

**Topology (`topology/minimal_topology.py`):** A 2-switch linear OpenFlow 1.3 topology (`s1`–`s2`, `failMode='secure'`) connects legitimate client `h_benign` (`10.0.0.1`, `s1:p1`) and attacker `h_attacker` (`10.0.0.2`, `s1:p2`) through `s1` and `s2` to victim service `h_server` (`10.0.0.3`, `s2:p2`). Both switches enforce an explicit software flow-table capacity proxy (`Flow_Table flow_limit=4096, overflow_policy=refuse`), reported strictly as `software_flow_table_occupancy_pct` rather than hardware TCAM (`DEC-003`).

**Zero-Carryover Hygiene (`DEC-007`, `DEC-008`, `DEC-014`):** Forwarding rules carry OpenFlow `cookie=0x10` and drop mitigation rules carry `cookie=0x20` (reserving `cookie=0x0` for the priority-0 table-miss rule). Between trials, the harness resets controller modes, waits for `packet_in_total` quiescence (zero new arrivals over `0.3 s`), flushes dynamic rules via `ovs-ofctl -O OpenFlow13 del-flows <sw> cookie=0x10/-1` and `cookie=0x20/-1` with a retry-guarded settle loop for lingering TCP `FIN`/`RST` retries, and raises a fatal `RuntimeError` if `get_dynamic_flow_count() != 0`.

**Concurrent Benign QoS Probes:** During every trial, `h_benign` simultaneously runs (1) a cached steady data-plane stream (`iperf3 -u -b 20M`), (2) an ICMP RTT probe (`ping -i 0.2`), and (3) a **control-plane-sensitive new-flow TCP probe** initiating fresh ephemeral-port TCP 3-way handshakes (`2 Hz` under flood scenarios, or `60 Hz` during benign flash-crowd stress) to `h_server:8088` so control-plane queuing delay directly manifests as legitimate connection setup latency and timeouts (`2.0 s` timeout).

### 4.2 `InSDN` Leakage Audit & Four SDN Observability Tiers

We downloaded raw `InSDN` (`Sharukesh/INSDN/Dataset.csv`, `140,906,680` bytes, `343,889` rows × `84` columns; SHA-256 `a93d51e1c2debc7246728578f22d84a442f156628be64b8c9bae5ccc5dd88a42` recorded in [insdn_manifest.json](file:///c:/Users/sijan/Desktop/intern/research/data/manifests/insdn_manifest.json)) and audited it programmatically (`src/data/insdn_loader.py`):
- **Identifier & Shortcut Leakage:** `86.44%` of attack flows originate from attack-only `Src IP`s (`3` overlapping IPs across `922` normal and `121,949` attack IPs); `60.65%` target attack-only `Dst IP`s; `Dst Port` strongly separates classes (`53`/`443` normal vs. `0`/`80` attack).
- **Massive Feature Duplication & Dead Columns:** Stripping identifier columns (`Flow ID`, `Src IP`, `Dst IP`, `Src Port`, `Timestamp`, `Dst Port`) exposes `125,252` feature-only duplicate rows (`36.42%` of the dataset) and `12` zero-variance columns. Removing duplicates and splitting stratified `70/15/15` yields `184,746` clean flows (`129,322` train / `27,712` val / `27,712` test).
- **Observability Tiers:** We benchmark 5 model families (`LogisticRegression`, `LightGBM`, `XGBoost`, `RandomForest`, `MLP`, single-threaded `n_jobs=1`) across four tiers: **`T1a`** (6 unidirectional OpenFlow counters), **`T1b`** (12 bidirectional counters), **`T2`** (25 header/flag features), and **`T3`** (all 65 clean `CICFlowMeter` numeric features).

### 4.3 Proposed Two-Stage Decoupled Defense (`A3`) & Single-Variable Ablation (`A0`–`A4`)

Informed directly by `EXP-0005`–`EXP-0007`, we designed **`A3_TwoStage_Gate_Decoupled_TableGuard`** ([two_stage_controller.py](file:///c:/Users/sijan/Desktop/intern/research/src/controller/two_stage_controller.py), [window_features.py](file:///c:/Users/sijan/Desktop/intern/research/src/features/window_features.py), [async_worker.py](file:///c:/Users/sijan/Desktop/intern/research/src/mitigation/async_worker.py)):

1. **O(1) Hot-Path Telemetry Accumulation:** Inside `_packet_in_handler`, zero ML executes. The controller updates lightweight per-`(dpid, in_port)` 250 ms rolling counters capturing 10 strictly IP-value- and port-value-agnostic behavioral features: `packet_in_rate_pps`, `unique_src_ip_ratio`, `src_ip_entropy_norm`, `unique_src_port_ratio`, `dst_ip_concentration`, `udp_ratio`, `tcp_syn_only_ratio`, `tcp_ack_or_est_ratio`, `pkt_len_mean`, and `pkt_len_std`.
2. **Stage-1 O(1) Rate Gatekeeper & Selective Flow-Table Guard:** During calm traffic (`rate < 30 pps` per edge port), Stage-2 ML is never invoked (`0` IPC overhead). When an edge port exceeds `30 pps` in the current 250 ms window, the port enters suspicious watch mode: the **Selective Flow-Table Guard** forwards packets via `OFPPacketOut` *without* installing per-flow `OFPFlowMod` table entries for unverified high-cardinality bursts (while continuing to install normal rules for non-suspicious ports), preventing switch table exhaustion during the Stage-2 classification window.
3. **Stage-2 Decoupled Out-of-Process ML Worker (Core 8):** Triggered 250 ms feature vectors are sent non-blockingly over a direct `multiprocessing.Pipe(duplex=True)` (avoiding `multiprocessing.Queue`'s feeder-thread incompatibility with `eventlet` monkey-patching) to a dedicated worker process pinned to Core 8 running a `Stage-2 Windowed LightGBM` model (`EXP-0008`). Upon positive attack classification ($P(\text{attack}) \ge 0.5$), the controller asynchronously installs a targeted, time-bounded priority-100 OpenFlow drop rule (`cookie=0x20`, `hard_timeout=5 s`, scoped to `(in_port, ipv4_dst, ip_proto)`) on edge switch `s1`, halting further `Packet-In` generation at the switch.

To isolate the causal effect of every single component, we compare five architectures changing one mechanism at a time:
- **`A0_Baseline_NoAI`**: Unmodified OpenFlow 1.3 reactive switch.
- **`A1_Sync_Light_LGBM`**: Synchronous per-`Packet-In` `T1a` LightGBM inside `_packet_in_handler` (best lightweight synchronous baseline from `EXP-0007`).
- **`A2_Decoupled_Async_WindowML`**: Off-path Core-8 Stage-2 Windowed LightGBM with targeted drop rules, running continuously on every active 250 ms window *without* Stage-1 gating or the Selective Flow-Table Guard.
- **`A3_TwoStage_Gate_Decoupled_TableGuard`**: Full proposed system (`A2` + Stage-1 O(1) gatekeeper + Selective Flow-Table Guard).
- **`A4_Static_Rate_Threshold`**: Pure non-ML heuristic installing drop rules immediately whenever any edge port exceeds `30 pps` (control baseline testing AI necessity under legitimate flash crowds).

---

## 5. Complete Experimental Audit Trail (`EXP-0001`–`EXP-0012`)

Every run — including failures, invalidations, and interruptions — is permanently preserved in [registry.csv](file:///c:/Users/sijan/Desktop/intern/research/experiments/registry.csv) and `experiments/manifests/`:

| Exp ID | Phase | Status | Key Outcome / Root Cause of Preserved Failure |
| :--- | :--- | :---: | :--- |
| `EXP-0001` | Phase 3 (Baseline A) | `FAILED` | `iperf3 -b 50M` TCP timed out; root-caused `veth` TX checksum offload drops in OVS `netdev` + WSL2 TCP `-b` pacing deadlock (`DEC-005`). |
| `EXP-0002` | Phase 3 (Baseline A) | `SUCCESS_WITH_CAVEAT` | Located no-AI CPU knee (`97.0%` at `1,500 pps`, `2,135 Packet-In/s`) & new-TCP collapse (`37.5%`). Retroactive audit flagged flow carryover on `s1_flows_peak` in Phases 3–7 (`DEC-007`). |
| `EXP-0003` | Phase 3/4 (Compute Calib) | `INVALID_CARRYOVER` | Invalidated by silent non-strict OpenFlow 1.3 `del-flows priority=10` failure; led to `cookie=0x10` masked flush + zero-flow assertion (`DEC-007`). |
| `EXP-0004` | Phase 3/4 (Compute Calib) | `FAILED` | Zero-flow assertion caught `8` in-flight flows after saturated Trial 5 (`2.0 ms`); led to post-saturation `packet_in_total` quiescence drain (`DEC-008`). |
| **`EXP-0005`** | **Phase 3/4 (Compute Calib)** | **`SUCCESS`** | **18/18 clean core-pinned trials (`N=3`); proved hard synchronous compute cliff between `1.0 ms` and `2.0 ms` at `250 pps`.** |
| **`EXP-0006`** | **Phase 4A (Offline InSDN)** | **`SUCCESS`** | **20 configs (4 tiers × 5 models) + `Dst Port` ablation; uncovered `Init Bwd Win Byts` fingerprint and `32x–63x` `batch=64` speedup (`DEC-010`).** |
| **`EXP-0007`** | **Phase 4B (Live Attribution)** | **`SUCCESS`** | **24/24 clean core-pinned trials (`N=3` × 8 pipelines); proved `batch=1` inference (`85.2%`) >> `T3` extraction (`4.7%`) and `0.03%` live flood detection on `T3+RF` (`DEC-011`).** |
| **`EXP-0008`** | **Phase 5A (Window Dataset)** | **`SUCCESS`** | **873 live windows across 7 regimes (disjoint seeds); `Static Rate` `94.0%` flash-crowd FPR vs. `Stage-2 LGBM` `0.0%` FPR & `1.0000` F1.** |
| `EXP-0009` | Phase 5B (Pilot Ablation) | `FAILED` | Trials 1–24 succeeded; Trial 25 (`A4` flash crowd) killed `iperf3` TCP control socket (`DEC-013`). Led to graceful `TimeoutExpired` handling + `N=5` expansion. |
| `EXP-0010` | Phase 5/6 (`N=5` Ablation) | `INTERRUPTED_HOST_SLEEP` | Interrupted at Trial 21/75 by host sleep; caught and fixed stale `d2m` burst timestamp edge case (`DEC-014`). |
| `EXP-0011` | Phase 5/6 (`N=5` Ablation) | `FAILED` | Failed at Trial 56/75 (`8` residual flows from lingering kernel TCP `FIN`/`RST` retries after `A4` false drops); fixed via retry-guarded flush settle loop (`DEC-014`). |
| **`EXP-0012`** | **Phase 6 (`N=5` Ablation)** | **`SUCCESS`** | **75/75 clean core-pinned trials (`N=5` unseen seeds `[301..305]` × 3 scenarios × 5 architectures) with Mann-Whitney U tests (`DEC-014`).** |

---

## 6. Empirical Results and Statistical Analysis

All metrics reported below are drawn verbatim from saved CSV/JSON artifacts under `experiments/results/`.

### 6.1 Baseline A Control-Plane Saturation Without AI (`EXP-0002`)

Sweeping spoofed UDP table-miss traffic from `0` to `1,500 pps` across `s1` and `s2` (each uncached spoofed packet triggers two `Packet-In`s, one at `s1` and one at `s2`) establishes the baseline capacity of an unmodified reactive `os-ken` controller (Table 1; source: [phase_summary.csv](file:///c:/Users/sijan/Desktop/intern/research/experiments/results/EXP-0002/phase_summary.csv)).

**Table 1: `EXP-0002` Baseline A (No-AI `os-ken`) Rate Sweep** *(Note: `s1` flow-table peak in Phases 3–7 had cross-phase carryover per `DEC-007` and is omitted from capacity claims).*

| Target Spoof (pps) | Controller `Packet-In` (pps) | Handler p50 / p99 (ms) | Event-Loop Lag p95 (ms) | Ctrl CPU Mean (%) | OVS CPU Mean (%) | Cached `iperf3` (Mbps / Loss%) | New-TCP Setup OK (%) | New-TCP Setup p95 (ms) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `0` | `17.2` | `0.31 / 0.61` | `0.97` | `1.35` | `23.43` | `20.0 / 0.0%` | `100.0` | `8.85` |
| `50` | `111.2` | `0.37 / 0.58` | `1.08` | `8.24` | `50.07` | `20.0 / 0.0%` | `100.0` | `9.53` |
| `150` | `304.1` | `0.36 / 0.65` | `1.06` | `22.35` | `89.59` | `20.0 / 0.0%` | `100.0` | `10.20` |
| `300` | `580.6` | `0.31 / 0.61` | `1.02` | `35.47` | `107.97` | `20.0 / 0.0%` | `100.0` | `14.80` |
| `600` | `1,160.2` | `0.25 / 0.48` | `0.99` | `64.68` | `206.13` | `20.0 / 0.0%` | `100.0` | `35.71` |
| `1,000` | `1,796.1` | `0.24 / 4.94` | `7.19` | `91.07` | `299.56` | `20.0 / 0.0%` | `100.0` | `2,165.02` |
| `1,500` | `2,135.3` | `0.23 / 4.33` | `7.01` | `96.98` | `274.21` | `20.0 / 0.0%` | `37.5` | `353.34` |

Two structural insights emerge immediately: (1) even with **zero AI**, single-threaded `os-ken` saturates near `~2,135 Packet-In/s` (`96.98%` CPU), inflating `eventlet` loop lag `7.2x` and collapsing legitimate new-TCP connection setup from `100.0%` (`8.85 ms` p95) to `37.5%` (`2,165 ms` p95 at `1,000 pps`); (2) **cached steady-state `iperf3` flows remain unaffected (`20.0 Mbps / 0.0% loss`)** because already-installed switch rules bypass the controller — proving that evaluating SDN-IDS defenses solely with long-lived `iperf3` flows completely masks control-plane collapse!

### 6.2 Core-Pinned Synchronous Compute-Budget Law (`EXP-0005`)

Pinning `os-ken` to Core 0 at a fixed sub-saturation spoofed flood (`250 pps`, generating `~475–488 Packet-In/s`) and sweeping synthetic synchronous CPU work $t_{\text{AI}} \in \{0.0, 0.25, 0.5, 1.0, 2.0, 4.0\}\text{ ms}$ across `N=3` seeds reveals a sharp queueing saturation cliff governed by the single-core service rate law $\mu_{\max}(t_{\text{AI}}) \approx 1000 / (t_{\text{base}} + t_{\text{AI}})$ with empirical base cost $t_{\text{base}} \approx 0.53\text{–}0.63\text{ ms}$ (Table 2; [aggregated_summary.csv](file:///c:/Users/sijan/Desktop/intern/research/experiments/results/EXP-0005/aggregated_summary.csv); Figure [fig02_exp0005_compute_budget_cliff.png](file:///c:/Users/sijan/Desktop/intern/research/figures/fig02_exp0005_compute_budget_cliff.png)).

**Table 2: `EXP-0005` Core-Pinned Synchronous Compute-Budget Calibration (`250 pps`, `N=3` Seeds, Mean ± 95% CI).**

| Sync Work (ms) | `Packet-In` (pps) | Handler p50 / p99 (ms) | Loop Lag p95 (ms) | Ctrl CPU (%) | New-TCP OK (%) | New-TCP p95 (ms) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `0.00` | `475.5 ± 8.9` | `0.32 / 0.55` | `1.03 ± 0.07` | `29.6 ± 4.6` | `100.0 ± 0.0` | `12.4 ± 2.8` |
| `0.25` | `487.9 ± 30.9` | `0.59 / 0.87` | `1.01 ± 0.04` | `44.4 ± 9.5` | `100.0 ± 0.0` | `18.9 ± 7.2` |
| `0.50` | `471.7 ± 2.0` | `0.85 / 1.16` | `1.06 ± 0.05` | `55.5 ± 1.9` | `100.0 ± 0.0` | `22.1 ± 2.2` |
| `1.00` | `477.7 ± 30.9` | `1.35 / 1.76` | `2.49 ± 2.07` | `78.9 ± 12.0` | `100.0 ± 0.0` | `48.9 ± 44.1` |
| **`2.00`** | **`395.6 ± 35.3`** | **`2.35 / 3.96`** | **`31.91 ± 4.33`** | **`97.4 ± 0.9`** | **`47.6 ± 10.2`** | **`1,293.7 ± 236.0`** |
| **`4.00`** | **`215.9 ± 12.0`** | **`4.41 / 6.08`** | **`24.94 ± 3.67`** | **`97.6 ± 0.6`** | **`16.7 ± 0.0`** | **`437.9 ± 515.0`** |

Between `1.0 ms` and `2.0 ms` of synchronous work per `Packet-In`, the controller crosses $\rho = \lambda / \mu_{\max} \ge 1$: CPU pins at `97.4%`, `eventlet` loop lag jumps `31x` (`1.03 -> 31.91 ms`), and benign new-TCP survival collapses from `100.0%` to `47.6%` (`1,294 ms` p95) at `2.0 ms` and `16.7%` at `4.0 ms`. This defines an exact empirical ceiling: **at just `250 pps` (`~500 Packet-In/s`), any synchronous AI pipeline exceeding `1.0–1.5 ms` per event induces catastrophic control-plane failure.**

### 6.3 `InSDN` Shortcut Leakage Audit & Offline Tier Benchmark (`EXP-0006`)

Benchmarking all 20 `(tier × model)` pairs on `184,746` deduplicated, leakage-stripped `InSDN` flows (Table 3; [offline_benchmark_summary.csv](file:///c:/Users/sijan/Desktop/intern/research/experiments/results/EXP-0006/offline_benchmark_summary.csv); Figures [fig01_insdn_leakage_and_tiers.png](file:///c:/Users/sijan/Desktop/intern/research/figures/fig01_insdn_leakage_and_tiers.png) and [fig03_exp0006_pareto_f1_vs_latency.png](file:///c:/Users/sijan/Desktop/intern/research/figures/fig03_exp0006_pareto_f1_vs_latency.png)) exposes two critical pitfalls:

1. **Testbed Fingerprints Explain "99.99%" Offline Accuracy:** Re-introducing `Dst Port` alone inflates `T1a` LightGBM from `0.9661` Macro F1 (`4.37%` FPR) to `0.9979` Macro F1 (`0.12%` FPR). Even without `Dst Port`, jumping from `T1b` (`0.9785` F1, `2.85%` FPR) to `T2` (`0.9999` F1, `0.01%` FPR) is driven primarily by `Init Bwd Win Byts` (LightGBM #1 feature, `importance = 404`), which acts as an OS/VM TCP receive-window fingerprint of the `InSDN` capture hosts (`DEC-010`).
2. **Per-Call Python/C-API Dispatch Dominates `batch=1` Latency:** Single-sample (`batch=1`) inference latency for `LightGBM` (`0.52–0.59 ms` p50), `XGBoost` (`0.34–0.46 ms` p50), and `RandomForest` (`5.50–7.01 ms` p50, violating `EXP-0005`'s `1.0 ms` budget across all four tiers) is nearly invariant to feature dimensionality (`6` vs. `65` features). Micro-batching (`batch=64`) reduces amortized per-flow latency by **`32.0x–63.0x`** (`0.0033–0.1143 ms/flow`), foreshadowing why decoupling and window/batch amortization beats naive feature pruning.

**Table 3: `EXP-0006` Selected Offline Baselines Across Observability Tiers (`184,746` Deduplicated `InSDN` Flows, `n_jobs=1`).**

| Tier (`# Feats`) | Model | Test Macro F1 | Test FPR | `batch=1` p50 / p95 (ms) | `batch=64` p50 / flow (ms) | Batch Speedup | Exceeds `1.0 ms` p95? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `T1a` (`6`) | `LogisticRegression` | `0.8632` | `29.15%` | `0.330 / 0.533` | `0.0055` | `59.9x` | No |
| `T1a` (`6`) | `LightGBM` | `0.9661` | `4.37%` | `0.588 / 0.908` | `0.0141` | `41.9x` | No |
| `T1a` (`6`) | `XGBoost` | `0.9658` | `6.43%` | `0.462 / 0.782` | `0.0103` | `45.0x` | No |
| `T1a` (`6`) | `RandomForest` | `0.9682` | `4.39%` | `5.503 / 7.313` | `0.0891` | `61.8x` | **Yes** |
| `T1a` (`6`) | `MLP` | `0.9367` | `13.64%` | `0.195 / 0.265` | `0.0033` | `58.5x` | No |
| `T1b` (`12`) | `LightGBM` | `0.9785` | `2.85%` | `0.553 / 0.827` | `0.0163` | `33.9x` | No |
| `T2` (`25`) | `LightGBM` *(win-size shortcut)* | `0.9999` | `0.01%` | `0.538 / 1.026` | `0.0134` | `40.2x` | **Yes** |
| `T3` (`65`) | `LightGBM` | `0.9998` | `0.02%` | `0.522 / 0.748` | `0.0133` | `39.2x` | No |
| `T3` (`65`) | `RandomForest` | `0.9998` | `0.03%` | `7.009 / 9.432` | `0.1143` | `61.3x` | **Yes** |

### 6.4 Live Component Attribution & Single-Packet Blindness (`EXP-0007`)

Deploying the actual serialized `EXP-0006` models synchronously inside core-pinned `os-ken` at `250 pps` across `N=3` seeds (`24/24` trials; Table 4; [aggregated_summary.csv](file:///c:/Users/sijan/Desktop/intern/research/experiments/results/EXP-0007/aggregated_summary.csv); Figure [fig04_exp0007_live_component_attribution.png](file:///c:/Users/sijan/Desktop/intern/research/figures/fig04_exp0007_live_component_attribution.png)) directly tests `H1` and `H2`.

**Table 4: `EXP-0007` Live Component-Level Attribution Inside Core-Pinned `os-ken` (`250 pps`, `N=3` Seeds, Mean Values).**

| Live Pipeline | Offline F1 | Base OFP p50 (ms) | Feat Extract p50 (ms) | Model Infer p50 (ms) | Total Handler p50 / p99 (ms) | Loop Lag p95 (ms) | Ctrl CPU (%) | New-TCP OK (%) | Live Attack Flags / Total `Packet-In` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `Baseline_A_NoAI` | — | `0.329` | `0.000` | `0.000` | `0.329 / 0.557` | `1.02` | `30.15` | `100.0` | — |
| `FeatsOnly_T1a_Light` | — | `0.351` | `0.014` | `0.000` | `0.366 / 0.788` | `1.07` | `34.40` | `100.0` | — |
| `FeatsOnly_T3_HeavyCIC` | — | `0.309` | `0.174` | `0.000` | `0.487 / 0.843` | `1.05` | `38.20` | `100.0` | — |
| `Baseline_B_T1a_LR` | `0.8632` | `0.312` | `0.010` | `0.287` | `0.613 / 1.050` | `1.04` | `43.98` | `100.0` | `102–109 / 5,148–5,155` |
| `Baseline_B_T1a_LGBM` | `0.9661` | `0.302` | `0.009` | `0.445` | `0.759 / 1.223` | `1.00` | `49.56` | `100.0` | `80–95 / 5,148–5,156` |
| `Baseline_B_T1a_XGB` | `0.9655` | `0.310` | `0.010` | `0.405` | `0.728 / 1.229` | `1.04` | `49.51` | `100.0` | `73–90 / 5,143–5,157` |
| **`Baseline_C_T1a_RF`** | **`0.9686`** | **`0.348`** | **`0.009`** | **`3.173`** | **`3.558 / 5.480`** | **`24.56`** | **`98.07`** | **`22.2`** | **`8–10 / 2,670–3,183`** |
| **`Baseline_C_T3_RF`** | **`0.9998`** | **`0.346`** | **`0.172`** | **`3.118`** | **`3.662 / 5.386`** | **`29.46`** | **`98.33`** | **`16.7`** | **`1 / 2,684–3,225 (0.03%)`** |

Three critical conclusions follow:
1. **`H1` Refuted and Refined:** Synchronous `batch=1` inference — not per-event feature extraction — is the dominant bottleneck. On `Baseline_C_T3_RF`, 65-feature `T3` extraction takes `0.172 ms` (`4.7%` of handler time), whereas `batch=1` RF inference consumes `3.118 ms` (`85.2%`). Even on `T1a_LGBM`, `batch=1` inference (`0.445 ms`) is `47x` slower than 6-feature extraction (`0.009 ms`) and adds `+19.4%` controller CPU at `250 pps` (`49.56%` vs. `30.15%`). Pruning features alone without moving inference off the synchronous per-`Packet-In` hot path cannot solve controller saturation.
2. **`H2` Confirmed Live:** `T3+RF` (`99.98%` offline F1) and `T1a+RF` (`96.86%` offline F1) both pin controller CPU at `98.1–98.3%`, explode `eventlet` loop lag `24x–29x`, cut processed `Packet-In` throughput by `45%`, and collapse legitimate new-TCP survival to `16.7–22.2%`.
3. **Single-Packet Observability Blindness:** Because spoofed floods trigger `Packet-In` on isolated 1-packet flows (`Tot Fwd Pkts=1, Bwd=0, IAT=0`), the `99.98%` offline `T3+RF` model flagged only **`1` out of `2,684–3,225` live `Packet-In`s (`0.03%`)** across all three seeds! Per-flow static classifiers are structurally blind at `Packet-In` #1 — justifying a shift to **windowed multi-packet OpenFlow behavioral telemetry** (`EXP-0008`).

### 6.5 Multi-Regime Windowed Telemetry Classifier (`EXP-0008`)

Collecting `873` live 250 ms `(dpid, in_port)` windows across 7 traffic regimes (`benign_steady`, `benign_flash_40hz`, `benign_flash_80hz`, `attack_spoof_udp_{150,500}pps`, `attack_spoof_syn_{150,500}pps`) using strictly disjoint training seeds `[101, 102]` and held-out test seeds `[201, 202]` ([stage2_evaluation_summary.csv](file:///c:/Users/sijan/Desktop/intern/research/experiments/results/EXP-0008/stage2_evaluation_summary.csv)) establishes why lightweight windowed ML outperforms static rate thresholds:

| Model (Held-Out Test Seeds `[201, 202]`) | Test Macro F1 | All-Benign FPR | Flash-Crowd FPR | UDP Flood Recall | SYN Flood Recall |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `Static_Rate_Threshold (>= 30 pps)` | `0.6257` | `70.62%` | **`93.98%`** | `100.0%` | `98.46%` |
| `Window_LogisticRegression` (10 feats) | `1.0000` | `0.00%` | `0.00%` | `100.0%` | `100.0%` |
| **`Stage2_Window_LightGBM` (10 feats)** | **`1.0000`** | **`0.00%`** | **`0.00%`** | **`100.0%`** | **`100.0%`** |

While static rate gating achieves `93.98%` false positives on legitimate TCP flash crowds (because flash crowds also exceed `30 pps`), both windowed linear and gradient-boosted models separate spoofed floods from single-source flash crowds cleanly using aggregate source-cardinality, entropy, and TCP `SYN`-vs-`ACK` ratios. *(Honest limitation noted in Section 7: `1.0000` held-out F1 reflects our single-host flash-crowd generator; multi-IP distributed flash crowds will narrow this separation margin and must be evaluated in future work.)*

### 6.6 Phase 6 Controlled Single-Variable Ablation (`EXP-0012`, `N=5` Unseen Seeds, 75/75 Trials)

We evaluated all five architectures (`A0`–`A4`) across `N=5` unseen random seeds `[301, 302, 303, 304, 305]` under three live scenarios: `spoof_udp_800pps`, `spoof_syn_800pps`, and `benign_flash_crowd_60hz` (zero attack traffic). Results are reported in Table 5 ([aggregated_summary.csv](file:///c:/Users/sijan/Desktop/intern/research/experiments/results/EXP-0012/aggregated_summary.csv)) and exact nonparametric Mann-Whitney U tests in Table 6 ([statistical_tests.json](file:///c:/Users/sijan/Desktop/intern/research/experiments/results/EXP-0012/statistical_tests.json)), visualized in Figures [fig05_exp0012_ablation_floods.png](file:///c:/Users/sijan/Desktop/intern/research/figures/fig05_exp0012_ablation_floods.png) and [fig06_exp0012_flash_crowd_vs_a4.png](file:///c:/Users/sijan/Desktop/intern/research/figures/fig06_exp0012_flash_crowd_vs_a4.png).

**Table 5: `EXP-0012` Single-Variable Ablation Across 3 Scenarios × 5 Architectures (`N=5` Seeds, Mean ± 95% CI).**

| Scenario | Architecture | Ctrl CPU (%) | Worker CPU (%) | Loop Lag p95 (ms) | `s1` Table Occ. (%) | `TABLE_FULL` | Stage-2 IPC | `d2m` (ms) | False Mit. | Benign TCP OK (%) | Benign TCP p95 (ms) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`spoof_udp_800pps`** | `A0` NoAI | `73.68 ± 2.27` | `0.24` | `1.51 ± 0.22` | `99.98 ± 0.00` | `8,052` | `0.0` | — | `0.0` | `100.0 ± 0.0` | `43.5 ± 8.6` |
| | `A1` Sync LGBM | `97.52 ± 0.20` | `0.29` | `10.59 ± 1.63` | `99.98 ± 0.00` | `5,798` | `0.0` | — | `0.0` | `79.96 ± 26.58` | `1,102.1 ± 496.9` |
| | `A2` Decoupled | `5.64 ± 0.48` | `0.54` | `0.93 ± 0.10` | `16.32 ± 1.29` | `0` | `27.0` | `378.3 ± 33.1` | `0.0` | `100.0 ± 0.0` | `12.4 ± 1.1` |
| | **`A3` 2-Stage+Guard** | **`5.13 ± 0.71`** | **`0.34`** | **`0.86 ± 0.08`** | **`1.47 ± 0.08`** | **`0`** | **`4.2`** | **`379.2 ± 85.7`** | **`0.0`** | **`100.0 ± 0.0`** | **`14.1 ± 5.2`** |
| | `A4` Static Rate | `2.56 ± 1.03` | `0.30` | `0.87 ± 0.10` | `5.64 ± 3.11` | `0` | `0.0` | `105.3 ± 79.0` | `0.0` | `100.0 ± 0.0` | `18.5 ± 7.4` |
| **`spoof_syn_800pps`** | `A0` NoAI | `71.44 ± 2.25` | `0.30` | `1.42 ± 0.24` | `99.98 ± 0.00` | `8,052` | `0.0` | — | `0.0` | `100.0 ± 0.0` | `39.1 ± 8.2` |
| | `A1` Sync LGBM | `96.84 ± 0.84` | `0.33` | `9.74 ± 0.38` | `99.98 ± 0.00` | `7,688` | `0.0` | — | `0.0` | `95.72 ± 4.86` | `1,793.5 ± 512.4` |
| | `A2` Decoupled | `5.82 ± 0.63` | `0.40` | `0.89 ± 0.04` | `17.38 ± 2.12` | `0` | `26.8` | `405.0 ± 55.6` | `0.0` | `100.0 ± 0.0` | `11.3 ± 1.3` |
| | **`A3` 2-Stage+Guard** | **`4.42 ± 0.52`** | **`0.28`** | **`0.89 ± 0.08`** | **`1.44 ± 0.00`** | **`0`** | **`4.2`** | **`315.5 ± 52.0`** | **`0.0`** | **`100.0 ± 0.0`** | **`16.6 ± 5.0`** |
| | `A4` Static Rate | `2.61 ± 0.58` | `0.30` | `0.82 ± 0.12` | `5.88 ± 1.53` | `0` | `0.0` | `112.0 ± 40.0` | `0.0` | `100.0 ± 0.0` | `13.2 ± 3.5` |
| **`benign_flash_60hz`** | `A0` NoAI | `23.52 ± 0.54` | `0.32` | `1.02 ± 0.03` | `30.82 ± 1.00` | `0` | `0.0` | — | `0.0` | `100.0 ± 0.0` | `15.5 ± 1.0` |
| | `A1` Sync LGBM | `32.63 ± 1.78` | `0.34` | `1.07 ± 0.03` | `28.94 ± 1.53` | `0` | `0.0` | — | `0.0` | `100.0 ± 0.0` | `19.9 ± 1.5` |
| | `A2` Decoupled | `23.01 ± 0.84` | `0.62` | `1.05 ± 0.02` | `28.88 ± 0.97` | `0` | `41.8` | — | `0.0` | `100.0 ± 0.0` | `15.5 ± 0.8` |
| | **`A3` 2-Stage+Guard** | **`23.50 ± 0.60`** | **`0.64`** | **`1.05 ± 0.03`** | **`28.92 ± 0.17`** | **`0`** | **`40.0`** | — | **`0.0`** | **`100.0 ± 0.0`** | **`15.6 ± 1.5`** |
| | **`A4` Static Rate** | **`3.75 ± 0.40`** | **`0.36`** | **`1.16 ± 0.20`** | **`19.31 ± 1.36`** | **`0`** | **`0.0`** | **`197.4 ± 20.4`** | **`4.0`** | **`60.97 ± 5.79`** | **`1,070.7 ± 24.5`** |

**Table 6: `EXP-0012` Two-Sided Mann-Whitney U Statistical Significance Tests (`N=5` Seeds per Group).**

| Scenario | Metric | Proposed (`A3`) Mean | Comparator Mean | Mann-Whitney $U$ | $p$-value | Interpretation |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| `spoof_udp_800pps` | Controller CPU (%) | `5.132` | `97.520` (`A1`) | `0.0` | **`0.0119`** | Significant (`19.0x` reduction) |
| `spoof_udp_800pps` | Benign TCP OK (%) | `100.000` | `79.958` (`A1`) | `25.0` | **`0.0067`** | Significant (eliminates timeouts) |
| `spoof_udp_800pps` | Event-Loop Lag p95 (ms) | `0.861` | `10.594` (`A1`) | `0.0` | **`0.0079`** | Significant (`12.3x` reduction) |
| `spoof_udp_800pps` | `s1` Table Occupancy (%) | `1.470` | `16.322` (`A2`) | `0.0` | **`0.0097`** | Significant (`11.1x` Guard gain) |
| `spoof_udp_800pps` | Controller CPU (%) | `5.132` | `73.676` (`A0`) | `0.0` | **`0.0079`** | Significant (`14.4x` vs. NoAI) |
| `spoof_syn_800pps` | Controller CPU (%) | `4.422` | `96.838` (`A1`) | `0.0` | **`0.0119`** | Significant (`21.9x` reduction) |
| `spoof_syn_800pps` | Benign TCP OK (%) | `100.000` | `95.716` (`A1`) | `20.0` | `0.0668` | Borderline on binary rate; `p95` latency `108x` better (`16.6` vs. `1,793.5 ms`) |
| `spoof_syn_800pps` | Event-Loop Lag p95 (ms) | `0.893` | `9.744` (`A1`) | `0.0` | **`0.0079`** | Significant (`10.9x` reduction) |
| `spoof_syn_800pps` | `s1` Table Occupancy (%) | `1.440` | `17.384` (`A2`) | `0.0` | **`0.0075`** | Significant (`12.1x` Guard gain) |
| `spoof_syn_800pps` | Controller CPU (%) | `4.422` | `71.440` (`A0`) | `0.0` | **`0.0119`** | Significant (`16.2x` vs. NoAI) |
| `benign_flash_60hz` | Benign TCP OK (%) | `100.000` | `60.968` (`A4`) | `25.0` | **`0.0075`** | Significant (prevents FP collapse) |
| `benign_flash_60hz` | False Mitigations (count) | `0.000` | `4.000` (`A4`) | `0.0` | **`0.0040`** | Significant (`0` vs. `4` blocks/run) |

### 6.7 Causal Decomposition of Architectural Gains

1. **Why Synchronous Lightweight ML Fails at Scale (`A1` vs. `A0`):** Even lightweight 6-feature `LightGBM` — which survived `250 pps` in `EXP-0007` — collapses at `800 pps`, driving CPU to `97.5%` (UDP) / `96.8%` (SYN), inflating `handler_p99` `10x` (`0.42 -> 4.22 ms`), spiking `eventlet` loop lag to `9.7–10.6 ms`, and blowing benign new-TCP p95 delay to `1,102–1,794 ms` (while flooding `s1` to `99.98%` occupancy with `5,798–7,688` `TABLE_FULL` refusals).
2. **Causal Effect of Async Decoupling + Targeted Mitigation (`A2` vs. `A1`):** Moving windowed ML onto Core 8 with targeted switch drop rules collapses controller CPU from `97.5%` to `5.6%` (`0.54%` worker CPU), restores `100.0%` benign TCP setup (`11.3–12.4 ms` p95), and eliminates `TABLE_FULL` refusals. However, during the `~378–405 ms` detection-to-mitigation (`d2m`) window, `A2` still installs `632–798` unverified spoofed flow entries (`16.3–17.4%` of `s1`'s table) and emits `26.8–27.0` Stage-2 IPC calls per 10 s run.
3. **Causal Effect of Stage-1 Gate + Selective Flow-Table Guard (`A3` vs. `A2`):** Adding the O(1) gatekeeper and flow-table guard bypasses `445–730` spoofed `OFPFlowMod` insertions per flood trial, slashing peak `s1` occupancy by **`11.1x` on UDP (`16.32 -> 1.47%`, $p=0.0097$)** and **`12.1x` on SYN (`17.38 -> 1.44%`, $p=0.0075$)**, while cutting Stage-2 IPC calls **`6.4x` (`27.0 -> 4.2`)** with no degradation to benign setup latency (`14.1–16.6 ms`).
4. **Causal Proof That AI Is Necessary (`A3` vs. `A4`):** Looking at flood scenarios alone, static rate limiting (`A4`) appears marginally faster (`d2m = 105–112 ms`, CPU `2.6%`). The benign flash-crowd scenario exposes why `A4` is operationally unsafe: `A4` falsely blocks `h_benign` `4.0` times per 10 s run on every seed (including killing `iperf3`'s TCP control teardown socket on 3 of 5 seeds — `0.0 Mbps` recorded), collapsing legitimate TCP completion to `60.97 ± 5.79%` and blowing p95 delay `68.5x` to `1,070.7 ms`. `A3` achieves **`100.0%` completion, `0.0` false mitigations, `15.6 ms` p95, and `23.50%` controller CPU** (indistinguishable from `A0`'s `23.52%`), whereas `A1` wastes `+9.1%` extra CPU (`32.63%`) on benign flash-crowd traffic.
5. **Transparent Nuances Observed in Raw Trial Logs:** (i) Under `spoof_syn_800pps`, `A1`'s binary new-TCP success rate remained `95.7%` (failing on 3 of 5 seeds, giving $p = 0.0668$ vs. `A3`), because TCP retries sometimes beat the `2.0 s` client timeout right before saturation — yet `A1`'s p95 setup delay still surged `108x` (`1,793.5 ms` vs. `16.6 ms`), confirming severe user-facing degradation. (ii) In `EXP-0012` raw logs ([trial_results.csv](file:///c:/Users/sijan/Desktop/intern/research/experiments/results/EXP-0012/trial_results.csv)), `benign_flash_crowd_60hz` Seed 304 `A0` recorded `0.0 Mbps` on the background UDP `iperf3` probe due to an `iperf3 -s` restart race right after Seed 303's `A4` false-block trial; its TCP completion (`100.0%`, `15.5 ms` p95) and CPU (`24.2%`) were unaffected. (iii) `EXP-0012`'s manifest notes `"dirty": true` solely from working-tree line-ending/registry edits prior to final commit.

---

## 7. Honest Limitations, Threats to Validity, and Venue Readiness

A rigorous academic evaluation requires stating clearly where experimental evidence stops:

1. **Internal / Platform Validity (WSL2 Userspace OVS vs. Native Linux Kernel OVS):** All live runs executed inside Ubuntu 22.04 Docker on Microsoft's WSL2 kernel (`5.15.153.1-microsoft-standard-WSL2`), requiring OVS userspace `netdev` datapath and standard `veth` links without `tc` (`sch_htb`/`sch_netem`) bandwidth/delay shaping. Although core pinning isolated `os-ken` (Core 0) from `ovs-vswitchd` (Cores 2–7), **absolute packet rates (`~2,135 Packet-In/s`) and userspace OVS CPU (`~35–148%`) will differ under native Linux kernel `openvswitch.ko` and `TCLink`**. Replicating `EXP-0007` and `EXP-0012` on a native DSAI Lab Ubuntu machine is mandatory before journal submission.
2. **Construct Validity (Software Flow-Table Proxy vs. Hardware TCAM):** OVS `flow_limit=4096` with `overflow_policy=refuse` accurately models bounded capacity exhaustion semantics, but does not capture physical TCAM lookup latency, wildcard rule-expansion overhead, or hardware ASIC flow-installation rates (`OFPFlowMod` rate limits on commercial switches).
3. **External Validity (Single-Host vs. Distributed Multi-IP Flash Crowds):** Our `benign_flash_crowd_60hz` workload originates from `h_benign` (`10.0.0.1`) opening `60` fresh ephemeral TCP connections/sec. Consequently, `unique_src_ip_ratio` and `src_ip_entropy_norm` strongly separate single-IP flash crowds from spoofed-IP floods, producing `1.0000` held-out F1 in `EXP-0008`. Under a **distributed multi-IP benign flash crowd** (hundreds of distinct legitimate client IPs arriving on the same aggregation uplink port), source-IP cardinality will rise alongside spoofed floods, forcing Stage-2 to rely on bidirectional TCP handshake completion (`tcp_ack_or_est_ratio`), payload variance, and flow-completion statistics — reducing the margin and potentially introducing non-zero false positives that must be measured empirically.
4. **External Validity (Topology Scale & Adversarial Evasion):** Our testbed uses 2 switches (`s1`–`s2`) and 3 hosts with 2 attack vectors (spoofed UDP and TCP SYN floods). Evaluating multi-switch campus/fat-tree topologies, low-rate slow-table-overflow attacks (as in *FTMaster*/*FloRa*), and protocol-constrained adversarial evasion against the 10-feature window model remain important future work.
5. **Candid Publication Venue Assessment:**
   - **Ready Today (with honest WSL2 disclosure):** Strong fit for a **peer-reviewed IEEE international/regional networking or security conference or workshop** (e.g., IEEE ANTS, IEEE ICCCNT, IEEE NetSoft Workshop, ACM/IEEE Student Research Symposium), where empirical systems measurement, negative/refined hypothesis reporting (`H1`), leakage auditing, and `N=5` controlled ablations stand out well above standard offline-only SDN-IDS papers.
   - **Required for Top-Tier Journals (e.g., IEEE TNSM, Elsevier Computer Networks):** Before submitting to a Q1 networking journal, the team should complete three targeted extensions during Weeks 9–12 once DSAI Lab native Ubuntu hardware is available: (a) native Ubuntu kernel `openvswitch.ko` + `TCLink` replication of `EXP-0007` and `EXP-0012`, (b) a **distributed multi-IP benign flash-crowd** evaluation (e.g., 20–50 distinct legitimate client IPs on a shared aggregation port), and (c) scaling to a 4–8 switch topology with a low-rate flow-table overflow attack baseline.

---

## 8. Reproducibility & Verification Checklist

Every claim, table, and figure in this report is reproducible from tracked code and immutable artifacts:
- **Unit & Integration Tests:** `pytest -v tests/` (`11/11` tests covering latency distributions, `InSDN` deduplication/tiers, live `T1a`/`T3` extractors, 10-feature window extraction, `multiprocessing.Pipe` worker IPC, and Stage-1/Stage-2 gate behavior).
- **Automated Integrity Verifier:** `python scripts/verify_reproducibility.py` validates all 12 registry entries, JSON manifests, dataset SHA-256, 3 executed notebooks, 6 figures, and 3 paper files.
- **Executed Analysis Notebooks:**
  - [01_insdn_leakage_audit_and_eda.ipynb](file:///c:/Users/sijan/Desktop/intern/research/notebooks/01_insdn_leakage_audit_and_eda.ipynb) -> generates [fig01_insdn_leakage_and_tiers.png](file:///c:/Users/sijan/Desktop/intern/research/figures/fig01_insdn_leakage_and_tiers.png)
  - [02_offline_vs_live_bottleneck_analysis.ipynb](file:///c:/Users/sijan/Desktop/intern/research/notebooks/02_offline_vs_live_bottleneck_analysis.ipynb) -> generates [fig02_exp0005_compute_budget_cliff.png](file:///c:/Users/sijan/Desktop/intern/research/figures/fig02_exp0005_compute_budget_cliff.png), [fig03_exp0006_pareto_f1_vs_latency.png](file:///c:/Users/sijan/Desktop/intern/research/figures/fig03_exp0006_pareto_f1_vs_latency.png), [fig04_exp0007_live_component_attribution.png](file:///c:/Users/sijan/Desktop/intern/research/figures/fig04_exp0007_live_component_attribution.png)
  - [03_phase6_ablation_and_paper_figures.ipynb](file:///c:/Users/sijan/Desktop/intern/research/notebooks/03_phase6_ablation_and_paper_figures.ipynb) -> generates [fig05_exp0012_ablation_floods.png](file:///c:/Users/sijan/Desktop/intern/research/figures/fig05_exp0012_ablation_floods.png), [fig06_exp0012_flash_crowd_vs_a4.png](file:///c:/Users/sijan/Desktop/intern/research/figures/fig06_exp0012_flash_crowd_vs_a4.png)
- **LaTeX Manuscript Draft:** [manuscript_draft.tex](file:///c:/Users/sijan/Desktop/intern/research/paper/manuscript_draft.tex) paired with verified [references.bib](file:///c:/Users/sijan/Desktop/intern/research/paper/references.bib).

---

## 9. Conclusion

Offline intrusion detection benchmarks create a dangerous illusion of deployment readiness for SDN. Through twelve controlled, reproducible experiments (`EXP-0001`–`EXP-0012`), we demonstrated empirically that: (1) static `InSDN` accuracy (`>99.9%`) is inflated by `36.4%` feature duplication and lab fingerprints (`Src IP`, `Dst Port`, `Init Bwd Win Byts`), while per-flow models suffer severe single-packet observability blindness (`0.03%` live spoofed flood detection on `T3+RF`); (2) inside a live core-pinned `os-ken` controller, synchronous `batch=1` inference dispatch — not feature extraction — drives control-plane saturation, crossing a hard queueing cliff between `1.0 ms` and `2.0 ms` per event at `250 pps`; and (3) moving to a **Two-Stage Decoupled Defense (`A3`)** combining an O(1) rate gatekeeper, a Selective Flow-Table Guard, and a Core-8 windowed LightGBM worker eliminates control-plane saturation (`97.5% -> 5.1%` CPU on UDP; `96.8% -> 4.4%` on SYN), slashes switch flow-table occupancy `11x–12x` with zero `TABLE_FULL` refusals, and preserves `100.0%` benign flash-crowd completion where static rate limiting fails (`61.0%`).
