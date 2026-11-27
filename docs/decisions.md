# Research Decision Log

All methodological, architectural, environmental, and scope decisions are logged chronologically with rationale and evidence.

---

## DEC-001: Sequenced Scope Prioritization (Live SDN Bottleneck First)
- **Date:** 2026-11-26
- **Context:** The 2026-11-25 pitch deck (`KU_DSAI_Simplified_Pitch_2026-11-25.pptx`) presented two linked problems (Live SDN Controller Bottleneck + Protocol-Constrained Adversarial Evasion) and left final scope selection (Unified Option A vs. Pure SDN Bottleneck Option B) pending Dr. Shakya's feedback. Today's active research directive prioritizes the live SDN controller bottleneck and lightweight AI defense.
- **Decision:** Build and validate the live SDN testbed and Baseline A–C bottleneck characterization first. Keep module boundaries (`src/features/`, `src/models/`, `src/mitigation/`) clean so protocol-constrained adversarial evaluation (Partner B) can integrate seamlessly if Dr. Shakya locks Option A.
- **Requires Supervisor Confirmation:** Confirm with Dr. Shakya whether the final manuscript targets Option B (pure live SDN bottleneck + lightweight defense) or Option A (unified bottleneck + constrained adversarial robustness) and whether a DPI-framed topology is desired.

## DEC-002: Controller Choice — `os-ken` Over Legacy `Ryu`
- **Date:** 2026-11-26
- **Context:** Upstream `ryu` is unmaintained and breaks on modern Python 3.10+/3.12 and `setuptools >= 68`.
- **Decision:** Standardize on OpenStack's maintained fork **`os-ken==2.11.0`** with OpenFlow 1.3 (`OFP_VERSION = 1.3`). Document its single-threaded `eventlet` cooperative event-loop architecture explicitly as a potential bottleneck factor to test empirically (not hide).

## DEC-003: Honest Flow-Table Metric Naming (Software Proxy vs. Hardware TCAM)
- **Date:** 2026-11-26
- **Context:** The pitch deck referred to measuring "TCAM %" in Mininet/OVS. However, Open vSwitch implements software flow tables in RAM, not hardware TCAM.
- **Decision:** Configure explicit per-bridge `Flow_Table` `flow_limit` and `overflow_policy=refuse` in OVS and report **`software_flow_table_occupancy_pct`** as a clearly defined **flow-table capacity proxy**, explicitly distinguishing it from hardware TCAM in all docs and paper drafts.

## DEC-004: Two-Tier Testbed Environment Strategy (Immediate Isolated Docker Prototype + Native Linux Validation)
- **Date:** 2026-11-26
- **Context:** Host audit of the local Windows 11 Home machine (AMD Ryzen 7 7840HS, 15.19 GB RAM, RTX 4050 6 GB, 53.45 GB free disk) showed that Docker Desktop runs on Microsoft's stock WSL2 kernel (`5.15.153.1-microsoft-standard-WSL2`), which explicitly disables `CONFIG_OPENVSWITCH`, `CONFIG_NET_SCH_HTB`, `CONFIG_NET_SCH_TBF`, and `CONFIG_NET_SCH_NETEM`, while enabling `CONFIG_VETH=y` and `CONFIG_TUN=y`. No VirtualBox/VMware/Hyper-V VM is currently installed.
- **Decision:**
  1. Immediately deploy an isolated Ubuntu 22.04 privileged Docker testbed (`docker/Dockerfile.sdn`) using OVS userspace datapath (`datapath_type=netdev`) and standard `veth` links (`Link`, not `TCLink`) to execute functional verification and Baseline A (`EXP-0001`) **without modifying host Windows/WSL2 configuration**.
  2. Explicitly log `ovs_datapath_mode=netdev` and `tc_shaping=unavailable` in every Docker experiment manifest and monitor `ovs-vswitchd` CPU independently from `os-ken`.
  3. Recommend acquiring a **native Ubuntu 22.04/24.04 LTS PC in DSAI Lab** (primary recommendation) or a dedicated **Ubuntu 22.04 VM (VMware Workstation Pro)** before running link-bandwidth-constrained (`TCLink`) final paper benchmarks so kernel `openvswitch.ko` and `sch_htb`/`sch_netem` are active without Windows/WSL2 scheduling jitter.

## DEC-005: Root Cause Diagnosis of `EXP-0001` Failure & Instrumentation Fix (`EXP-0002`)
- **Date:** 2026-11-26
- **Context:** `EXP-0001` passed pre-test `pingAll` (0.00% loss) but failed in Phase 1 (`rate_0pps`) with `iperf3 -c 10.0.0.3 -b 50M -t 12 -J` timing out after 32 s. `EXP-0001` logs and manifest are permanently preserved as `FAILED`.
- **Empirical Root Cause (Verified via Controlled Diagnostic):**
  1. In OVS `netdev` userspace mode (`AF_PACKET`), Linux `veth` TX checksum/TSO/GSO offload leaves TCP checksums uncomputed, causing the receiving kernel to silently drop TCP SYN frames (while ICMP `ping` succeeds because ICMP checksums are computed in software). Disabling offload via `ethtool -K <intf> tx off rx off sg off tso off gso off gro off` restored TCP connectivity immediately (unpaced TCP achieved 1.05 Gbps).
  2. Ubuntu 22.04's `iperf3` TCP `-b` pacing option stalled during teardown on the WSL2 kernel (which lacks `sch_fq`/`tc` pacing support), whereas `iperf3 -u -b 20M` completed cleanly with 0% loss and 0.033 ms jitter without pegging `ovs-vswitchd` CPU.
- **Decision:** Disable `veth` offload automatically when `datapath == "user"` in `topology/minimal_topology.py`, use paced UDP (`iperf3 -u -b 20M`) for steady data-plane goodput/jitter/loss alongside our live TCP `new_flow_probe` (2 fresh TCP handshakes/sec) and ICMP `ping`, and execute `EXP-0002` across `[0, 50, 150, 300, 600, 1000, 1500]` pps.

## DEC-006: Scope Locked to Option B (Pure Live SDN Bottleneck & Lightweight Defense)
- **Date:** 2026-11-26
- **Context:** User confirmed narrowing final research scope to **Pure Live SDN Bottleneck + Lightweight Defense** (dropping the parallel constrained adversarial evasion track from the 12-week deliverable), and noted that a native DSAI Lab Ubuntu machine is not immediately available today but can be arranged for later benchmark replication.
- **Decision:**
  1. Lock manuscript scope exclusively to empirical profiling of live SDN controller bottlenecks (offline vs. live AI-IDS divergence, component-level latency/CPU attribution) and controlled evaluation of lightweight architectural/feature/scheduling defenses.
  2. Maintain strict portability between the isolated Docker `netdev` container (for Phases 2–5 development & calibration) and native Ubuntu kernel OVS + `TCLink` (for Phase 6–7 final replication once DSAI Lab access is arranged).
  3. Introduce dedicated CPU core pinning (`taskset`: core 0 for `os-ken`, core 1 for traffic generator, cores 2–7 for `ovs-vswitchd`) starting with `EXP-0003` to eliminate CPU contention between userspace OVS and the controller.

## DEC-007: Flow-Carryover Audit (`EXP-0002` Caveat & `EXP-0003` Invalidation -> Cookie-Masked Flush Fix)
- **Date:** 2026-11-26
- **Context:** Auditing `EXP-0003` revealed that trials `0.25, 0.50, 2.00, 4.00 ms` observed only `~13 pps` `Packet-In` instead of `~480 pps`, while `0.00` and `1.00 ms` observed `~480 pps`. Root-cause inspection revealed that `ovs-ofctl -O OpenFlow13 del-flows <sw> "priority=10"` silently failed (non-strict OpenFlow 1.3 `del-flows` rejects `priority=` matching, and `stderr` was suppressed with `check=False`).
- **Retroactive Audit of `EXP-0002`:** Inspecting `EXP-0002`'s per-phase `resource_samples` showed that Phases 3–7 started with residual dynamic flows from prior phases (`635`, `1805`, `3498`, `3719`, `2956` flows on `s1`). While `EXP-0002`'s `Packet-In` rates, controller CPU saturation (`1.35% -> 96.98%`), handler p99, and `eventlet` loop lag remained valid (because each phase used a distinct generator seed so incoming spoofed packets still missed the table), its `s1_flows_peak` and `table_full_errors` in Phases 3–7 were confounded by carryover. Both `EXP-0002` and `EXP-0003` artifacts are preserved permanently without deletion or overwrite.
- **Decision:**
  1. Tag all dynamic rules with OpenFlow `cookie=0x10` (`cookie=0x0` reserved for priority-0 table-miss).
  2. Replace `flush_dynamic_flows()` with `ovs-ofctl -O OpenFlow13 del-flows <sw> cookie=0x10/-1` (`check=True`) followed by a hard assertion `get_dynamic_flow_count(sw) == 0` (verified empirically in Docker).
  3. Pass unique deterministic `trial_seed = seed * 100 + level_idx` per trial and execute clean zero-carryover calibration as **`EXP-0004`**.

## DEC-008: Post-Saturation Queue-Drain Quiescence Before Flow Flush (`EXP-0004` -> `EXP-0005`)
- **Date:** 2026-11-26
- **Context:** In `EXP-0004`, Trials 1–5 (`0.00 -> 2.00 ms`) executed cleanly and revealed a sharp saturation cliff at `2.00 ms` (`ctrl_cpu=97.6%`, `event_loop_lag_p95=34.68 ms`, `new_flow_ok=50.0%`). Immediately after Trial 5, our zero-flow assertion caught `8` residual dynamic flows on `s1` because `flush_dynamic_flows()` ran *before* `cooldown_s` while `os-ken`'s saturated socket buffer was still emitting the last in-flight `OFPFlowMod` messages from Trial 5.
- **Decision:** Preserve `EXP-0004` permanently, reset `inject_cpu_ms = 0.0`, sleep `cooldown_s`, wait for `packet_in_total` quiescence (zero new `Packet-In`s over 0.3 s), and *then* run `flush_dynamic_flows()` + zero-flow assertion before each trial in **`EXP-0005`**.

## DEC-009: Hybrid Engineering Standard — Tested `.py` Core + Interactive `.ipynb` Analysis Notebooks
- **Date:** 2026-11-26
- **Context:** User asked whether using `.ipynb` notebooks would be better for the ML/data pipeline.
- **Technical Critique:** Notebooks excel at interactive EDA, leakage inspection, and generating paper-ready visuals for weekly supervisor meetings, **but** putting core data-cleaning, training, or SDN code solely inside `.ipynb` files breaks automated `pytest` verification, risks hidden-state/out-of-order execution bugs, creates noisy Git diffs, and cannot be imported directly into `osken-manager` or automated multi-seed Mininet runners.
- **Decision:** Keep all data loading, deduplication, observability-tier feature mapping, model training, serialization, and live SDN controllers in tested, config-driven `.py` modules under `src/` and `scripts/`. Pair them with clean, executed `.ipynb` notebooks under `notebooks/` that import `src/` and visualize saved `experiments/results/` CSV/JSON artifacts.

## DEC-010: `EXP-0006` Findings — `Init Bwd Win Byts` Shortcut & Per-Call `batch=1` Dispatch Bottleneck
- **Date:** 2026-11-26
- **Context:** `EXP-0006` benchmarked 5 model families (`LogisticRegression`, `LightGBM`, `XGBoost`, `RandomForest`, `MLP`) across 4 observability tiers on deduplicated, leakage-stripped `InSDN` (`184,746` unique rows after removing `125,252` feature duplicates = `36.4%`).
- **Two Critical Findings:**
  1. **Hidden Lab-Stack Fingerprint (`Init Bwd Win Byts`):** Feature-importance auditing of `T2_Header_Flags` (`0.9999` F1, `0.01%` FPR vs. `0.9785` F1, `2.85%` FPR on `T1b`) revealed `Init Bwd Win Byts` as the #1 feature (`importance=404`), acting as a testbed OS/VM TCP receive-window fingerprint alongside the `Dst Port` shortcut (`+Dst Port` artificially jumped `T1a` LightGBM from `0.9661` F1 / `4.37%` FPR to `0.9979` F1 / `0.12%` FPR).
  2. **Per-Call Dispatch Overhead Dominates `batch=1` Inference:** Single-sample (`batch=1`) CPU inference for `LightGBM` (`0.52–0.59 ms` p50, `0.75–1.03 ms` p95) and `RandomForest` (`5.50–7.01 ms` p50, `7.01–9.43 ms` p95) was virtually invariant to feature count (`6` vs `65` features!), whereas micro-batching (`batch=64`) reduced per-flow latency by **32x–63x** (`0.003–0.114 ms/flow`).
- **Decision:**
  1. Never claim `99.99%` `T2` accuracy without explicitly disclosing the `Init Bwd Win Byts` testbed shortcut; keep `T1a`/`T1b` (strictly OpenFlow-native counters) and live Mininet traffic evaluation central.
  2. In Phase 4B (`EXP-0007`), deploy `Baseline B` (`LightGBM` + `LogisticRegression` on native OpenFlow features) and `Baseline C` (`RandomForest` + synchronous multi-feature extraction) **live inside `os-ken`** to empirically test `H1` (feature extraction vs. inference vs. event-loop blocking) before building our Phase 5 decoupled micro-batched + Stage-1 gatekeeper defense.

## DEC-011: `EXP-0007` Live Component Attribution — Refutation of Naive Feature-Extraction Assumption & Single-Packet Observability Blindness
- **Date:** 2026-11-26
- **Context:** Executed 24 core-pinned live trials (`N=3` seeds × 8 factorial pipelines) inside `ku-dsai-sdn:0.2` at `250 pps` spoofed table-miss flood (`~475–490 Packet-In/s`, `0` carryover).
- **Three Major Empirical Findings:**
  1. **Hypothesis `H1` Refined (Synchronous `batch=1` Inference Dominates Over Feature Extraction):** On `Baseline_C_T3_RF`, median handler time (`3.66 ms`) decomposed into `base_ofp = 0.35 ms` (`9.5%`), `T3 65-feature extraction = 0.17 ms` (`4.7%`), and **`batch=1` RF inference = `3.12 ms` (`85.2%`)**. Even for lightweight `T1a` (`0.010 ms` extraction), synchronous `batch=1` `LightGBM`/`XGBoost`/`LR` inference (`0.29–0.44 ms`) was `29×–44×` larger than extraction and added `+14%–20%` controller CPU at `250 pps`. Thus, feature pruning alone without removing synchronous `batch=1` inference from `_packet_in_handler` does NOT solve the bottleneck.
  2. **Hypothesis `H2` Strongly Supported Live:** `T3+RF` (`99.98%` offline F1) and `T1a+RF` (`96.86%` offline F1) both saturated `os-ken` (`98.1%–98.3%` CPU), spiked `eventlet` loop lag `24×–29×` (`1.02 -> 24.6–29.5 ms`), dropped `45%` of `Packet-In` throughput, and collapsed legitimate new-TCP connection setup to **`16.7%–22.2%`**, whereas `T1a+LGBM`/`T1a+XGB` sustained `100.0%` setup success at `~49.5%` CPU at `250 pps`.
  3. **Single-Packet `Packet-In` Observability Blindness:** Because spoofed table-miss floods arrive as isolated 1-packet flows (`Tot Fwd Pkts=1, Bwd=0, IAT_std=0`), offline `InSDN`-trained `T3+RF` (`99.98%` offline F1) classified `2,860–3,225` live attack `Packet-In`s as Normal and flagged only **`1`** (`0.03%` detection rate!).
- **Decision for Phase 5:** Design the proposed defense directly from these three measured mechanisms:
  - **Stage 1 (O(1) In-Controller Fast Gate + Flow-Table Guard):** Zero ML inside `_packet_in_handler`; tracks sliding-window aggregate OpenFlow telemetry (`Packet-In` rate, unique `src_ip` ratio, `dst_ip` concentration, single-packet flow ratio, flow-table occupancy proxy).
  - **Stage 2 (Decoupled Out-of-Process Worker on a Separate CPU Core):** Runs micro-batched / windowed lightweight ML off the `eventlet` loop + GIL to separate spoofed DDoS floods from legitimate flash crowds and pushes targeted OpenFlow mitigation rules back asynchronously.
  - Evaluate strictly one variable at a time against `Baseline A`, `Baseline B (Sync LGBM)`, and `Baseline C (Sync RF)` across both moderate (`250 pps`) and high (`600–1000 pps`) flood loads + legitimate flash-crowd scenarios!

## DEC-012: Pre-Registered Phase 5 Primary Metrics, Ablation Matrix (`A0–A4`), and Flash-Crowd Control
- **Date:** 2026-11-27
- **Context:** Before implementing Phase 5 defenses, we pre-register the exact evaluation protocol and success criteria (Section 13) to prevent post-hoc metric shopping or naive-threshold cheating.
- **Decision:**
  1. **Windowed OpenFlow Feature Representation (10 IP-value-agnostic features per 250 ms `(dpid, in_port)` window):** `packet_in_rate_pps`, `unique_src_ip_ratio`, `src_ip_entropy_norm`, `unique_src_port_ratio`, `dst_ip_concentration`, `udp_ratio`, `tcp_syn_only_ratio`, `tcp_ack_or_est_ratio`, `pkt_len_mean`, `pkt_len_std`. Trained on live multi-regime Mininet telemetry (`EXP-0008`: steady benign, benign TCP flash crowds, variable-length spoofed UDP floods, spoofed TCP SYN floods) using strictly disjoint Train vs. Test seeds.
  2. **5-Architecture Single-Variable Ablation (`EXP-0009`):** `A0_Baseline_NoAI`, `A1_Sync_Light_LGBM`, `A2_Decoupled_Async_WindowML`, `A3_TwoStage_Gate_Decoupled_TableGuard`, and `A4_Static_Rate_Threshold` evaluated under BOTH `800 pps` spoofed flood AND `60 conn/s` legitimate TCP flash crowd (`N=3` core-pinned seeds; `N=5` in Phase 6 final validation).
  3. **Locked Success Criteria:** `A3` must simultaneously (a) keep benign new-TCP survival `>= 95%` and controller CPU `< 30%` under `800 pps` flood, (b) keep `s1` flow-table occupancy strictly below `A2` with `0` `TABLE_FULL` refusals, and (c) preserve `>= 95%` legitimate completion during benign flash crowds where `A4` fails.







