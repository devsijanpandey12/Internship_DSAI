# Environment Audit & Reproducible Setup Guide

## 1. Host Machine Audit (Measured 2026-11-26)

| Component | Measured Value | Research Implication |
| :--- | :--- | :--- |
| **OS** | Microsoft Windows 11 Home (Build 26300) | No native Linux kernel; Hyper-V Manager unavailable on Home edition (`VirtualMachinePlatform` is active for WSL2). |
| **CPU** | AMD Ryzen 7 7840HS (8 cores / 16 threads, hardware virtualization enabled) | Strong CPU capacity; adequate for multi-process SDN emulation when core-pinned. |
| **RAM** | 15.19 GB total (~5.3 GB free under Windows + Docker Desktop; 7.4 GB allocated to WSL2) | Running a heavy GUI VM alongside Windows + IDE will create memory pressure; keep testbed lightweight. |
| **GPU** | NVIDIA GeForce RTX 4050 Laptop GPU (6 GB VRAM, Driver 591.74) | Useful for offline DL baseline training (`MLP`, `CNN-LSTM`), NOT used for live CPU controller inference. |
| **Storage** | C: 53.45 GB free / 474.72 GB total | Tight for full `CIC-DDoS2019` (uncompressed >15 GB) + a 30 GB VM disk; curate subsets or use DSAI Lab storage. |
| **Installed Tools** | Git 2.44, Python 3.11, `uv` 0.10.11, Docker Desktop 29.9.3 (WSL2) | VirtualBox, VMware, Multipass, and Ubuntu WSL distro are NOT installed. |

## 2. Empirical WSL2 Kernel Capability Audit

Inspecting `/proc/config.gz` inside Docker Desktop's WSL2 Linux kernel (`5.15.153.1-microsoft-standard-WSL2`) revealed:

- `CONFIG_VETH=y`, `CONFIG_BRIDGE=y`, `CONFIG_TUN=y`, `CONFIG_NET_CLS_U32=y`
- `# CONFIG_OPENVSWITCH is not set` (**kernel OVS datapath unavailable**)
- `# CONFIG_NET_SCH_HTB is not set` (**Mininet `TCLink` bandwidth shaping unavailable**)
- `# CONFIG_NET_SCH_TBF is not set` (**token-bucket rate shaping unavailable**)
- `# CONFIG_NET_SCH_NETEM is not set` (**emulated link delay/loss unavailable**)
- `/lib/modules` does not exist inside stock WSL2.

**Consequence:** Standard Mininet with kernel OVS (`OVSSwitch` default `system` datapath) and `TCLink` **cannot run unmodified** on stock Windows 11 WSL2.

## 3. Environment Options Comparison & Recommendation

| Option | Kernel OVS | `TCLink` (`htb`/`netem`) | Timing Determinism | Host Impact | Recommendation |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **A. Native Ubuntu 22.04/24.04 PC (DSAI Lab)** | Yes | Yes | **Highest** (bare metal, `taskset`) | None on laptop | **BEST for final paper experiments** (request lab machine from Dr. Shakya) |
| **B. Dedicated Ubuntu 22.04 VM (VMware Workstation Pro / VirtualBox)** | Yes | Yes | Good (hypervisor jitter caveats under WHPX) | Installs hypervisor + ~25 GB disk + 4–6 GB RAM | **BEST local laptop fallback** if no DSAI Lab Linux PC is available |
| **C. Custom WSL2 Linux Kernel + Ubuntu/Docker** | Yes | Yes | Moderate (shares Windows scheduler) | Modifies global `%USERPROFILE%\.wslconfig` (risk to Docker Desktop) | Only if user explicitly approves kernel swap |
| **D. Privileged Ubuntu 22.04 Docker Container + OVS `netdev` Userspace** | No (`netdev` userspace) | No (uses standard `Link`) | Moderate (`ovs-vswitchd` uses more CPU; logged separately) | **Zero host modification** | **IMMEDIATE Phase 1–3 development & Baseline A smoke test** |

## 4. Reproducible Container Build & Run (Tier 1 Local Testbed)

```powershell
# Build isolated SDN testbed image from research/
docker build -f docker/Dockerfile.sdn -t ku-dsai-sdn:0.1 .

# Run interactive shell or experiment with workspace mounted
docker run --rm --privileged --network none `
  -v "${PWD}:/workspace" `
  ku-dsai-sdn:0.1 python3 scripts/run_exp0001_baseline_no_ai.py --config configs/exp0002_baseline_no_ai.yaml
```

> **OVS `netdev` Userspace Note:** When running under stock WSL2 (`OVS_DATAPATH_MODE=netdev`), `topology/minimal_topology.py` automatically disables `veth` TX/RX/TSO/GSO/GRO checksum offloading via `ethtool` to prevent TCP packet drops across `AF_PACKET` sockets.

*(Note: `--network none` guarantees full network isolation so no emulated attack traffic can ever leave the container.)*

## 5. Native Ubuntu 22.04 Setup (Tier 2 Final Benchmark Environment)

When moving to a DSAI Lab Ubuntu machine or Ubuntu VM, the exact same repository code runs natively with kernel OVS (`datapath_type=system`) and `TCLink`:

```bash
sudo apt-get update && sudo apt-get install -y \
  mininet openvswitch-switch iperf3 hping3 iproute2 tcpdump python3-venv python3-pip
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[sdn,ml,dev]"
```
