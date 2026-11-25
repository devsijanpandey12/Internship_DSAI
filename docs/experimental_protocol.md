# Experimental Protocol & Measurement Standards

## 1. Core Measurement Rules

1. **Unique Immutable Experiment IDs:** Every run receives a sequential ID (`EXP-0001`, `EXP-0002`, ...) recorded in `experiments/registry.csv` with a full JSON manifest in `experiments/manifests/<EXP_ID>.json`. Previous results are never overwritten.
2. **Failed Runs Are Preserved:** If a run crashes, saturates the generator instead of the controller, or refutes the hypothesis, its logs and metrics remain in `experiments/` and its failure mode is documented.
3. **Distributions Over Means:** Latency metrics MUST report `count`, `mean`, `median (p50)`, `p95`, `p99`, and `max` — never averages alone.
4. **Software Flow Table vs. Hardware TCAM Honesty:** Open vSwitch uses software hash/megaflow tables in Linux RAM, not physical hardware TCAM. Where we cap flow-table capacity using `ovs-vsctl` (`Flow_Table flow_limit=N overflow_policy=refuse`), we report **`software_flow_table_occupancy`** (`active_flows / configured_flow_limit`) as a documented **TCAM capacity proxy**, never claiming physical TCAM measurement.
5. **Separate Accounting of Testbed Overhead:** Monitor **controller process CPU/RSS**, **`ovs-vswitchd` process CPU/RSS**, and **traffic generator CPU/RSS** independently so switch or generator bottlenecks are never misattributed to the controller.
6. **Low-Overhead Telemetry:** Per-packet measurements use in-memory pre-allocated lists/arrays written to disk only after each measurement window/run completes (never synchronous disk/CSV flushes inside `OFPPacketIn`).
7. **Clock Synchronization:** Use `time.perf_counter_ns()` for intra-process durations and `time.monotonic_ns()` for event-loop lag and inter-process aligned intervals within the same Linux kernel namespace.
8. **Statistical Rigor (Phase 4+):** Comparative evaluations use `N >= 5` repeated runs with distinct random seeds, reporting mean +/- 95% CI (or median + IQR for skewed latencies) and nonparametric significance tests (Mann-Whitney U / Wilcoxon signed-rank with Holm-Bonferroni correction).

## 2. Minimal Experiment 1 Protocol (`EXP-0001`: Baseline A — SDN Without AI)

### Purpose
Validate that the isolated Mininet + Open vSwitch + `os-ken` testbed starts cleanly, forwards traffic via OpenFlow 1.3, and produces clean, monotonic, low-noise baseline measurements of controller overhead **before** adding any feature extraction or ML/DL inference.

### Topology (Minimal 2-Switch Linear)
```text
[h_benign (10.0.0.1)] ----\
                           (s1) -------- (s2) ---- [h_server (10.0.0.3)]
[h_attacker (10.0.0.2)] --/  ^            ^
                             |            |
                        [os-ken OpenFlow 1.3 Controller (127.0.0.1:6653)]
```
- `s1`, `s2`: Open vSwitch (`OpenFlow13`, `failMode='secure'`, explicit `flow_limit` configured on Table 0, e.g., `4096` with `overflow_policy=refuse` so flow-table pressure is observable without silent unbounded growth).
- `h_benign` (`10.0.0.1`): Generates steady benign traffic (`iperf3` TCP stream + concurrent ICMP `ping` RTT/loss probe to `h_server`).
- `h_attacker` (`10.0.0.2`): Generates controlled spoofed-source-IP/port UDP packets (`Scapy` / raw AF_PACKET paced sender) targeting `h_server` (`10.0.0.3:9999`), forcing table-miss `Packet-In` events at `s1`.
- `h_server` (`10.0.0.3`): Runs `iperf3 -s` and receives traffic.

### Load Sweep
Run isolated 15-second load phases (with 3-second warmup + flow-table flush between phases) at target spoofed table-miss rates:
`[0 (benign-only), 50, 150, 300, 600, 1000]` packets/sec (exact rates configurable via `configs/exp0001_baseline_no_ai.yaml`).

### Metrics Collected Per Phase
1. `packet_in_count` and achieved `packet_in_rate_pps` (controller-observed vs. sender-attempted).
2. `packet_in_handler_ms`: `p50`, `p95`, `p99`, `max` (time inside `_packet_in_handler` including parsing + `OFPFlowMod` + `OFPPacketOut` dispatch).
3. `event_loop_lag_ms`: `p50`, `p95`, `p99`, `max` measured by a dedicated 50 ms `eventlet` heartbeat greenlet (directly reveals cooperative scheduling starvation!).
4. `controller_cpu_pct` (mean, peak) and `controller_rss_mb` (via `psutil.Process(controller_pid)`).
5. `ovs_vswitchd_cpu_pct` (mean, peak) and `generator_cpu_pct` (to detect testbed contention).
6. `s1_flow_count_peak` and `s1_flow_table_occupancy_pct` (`peak / flow_limit`).
7. `benign_iperf_mbps` (mean TCP goodput `h_benign -> h_server`), `benign_rtt_p50_ms`, `benign_rtt_p95_ms`, `benign_packet_loss_pct`.

### Success Criteria for `EXP-0001`
1. **Connectivity & Control Verification:** 0% packet loss on pre-test `pingall`; OpenFlow 1.3 handshake completes on both `s1` and `s2`; benign `iperf3` completes cleanly in the `0 pps` control phase.
2. **Load Fidelity:** Controller observes increasing `Packet-In` rate scaling with target rate (or explicitly reveals where generator/OVS/controller saturates).
3. **Attribution Clarity:** Separate `os-ken`, `ovs-vswitchd`, and generator CPU telemetry cleanly identifies which component hits resource limits first.
4. **Reproducible Artifacts:** Structured manifest JSON, per-phase CSV summary, raw latency arrays, and full logs are saved under `experiments/` and indexed in `experiments/registry.csv`.
