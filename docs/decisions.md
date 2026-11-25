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
