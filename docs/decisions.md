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



