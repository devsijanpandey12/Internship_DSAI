"""Minimal 2-switch Mininet topology for Baseline A live SDN controller experiments."""

from __future__ import annotations

import os
import subprocess
from typing import Any

from mininet.link import Link
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController


HOST_SPECS = {
    "h_benign": {"ip": "10.0.0.1/24", "mac": "00:00:00:00:00:01"},
    "h_attacker": {"ip": "10.0.0.2/24", "mac": "00:00:00:00:00:02"},
    "h_server": {"ip": "10.0.0.3/24", "mac": "00:00:00:00:00:03"},
}


def detect_ovs_datapath() -> str:
    """Return Mininet OVSSwitch datapath parameter ('kernel' or 'user')."""
    mode = os.environ.get("OVS_DATAPATH_MODE", "").lower()
    if mode == "system":
        return "kernel"
    if mode == "netdev":
        return "user"
    if os.path.isdir("/sys/module/openvswitch"):
        return "kernel"
    return "user"


def build_minimal_network(
    controller_ip: str = "127.0.0.1",
    controller_port: int = 6653,
    openflow_version: str = "OpenFlow13",
    flow_table_limit: int = 4096,
    overflow_policy: str = "refuse",
) -> tuple[Mininet, dict[str, Any]]:
    """Construct and start the minimal 2-switch topology with explicit OVS flow_limit."""
    datapath = detect_ovs_datapath()
    net = Mininet(controller=None, switch=OVSSwitch, link=Link, autoSetMacs=False)

    net.addController(
        "c0",
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port,
    )

    s1 = net.addSwitch(
        "s1",
        dpid="0000000000000001",
        protocols=openflow_version,
        datapath=datapath,
        failMode="secure",
    )
    s2 = net.addSwitch(
        "s2",
        dpid="0000000000000002",
        protocols=openflow_version,
        datapath=datapath,
        failMode="secure",
    )

    h_benign = net.addHost("h_benign", ip=HOST_SPECS["h_benign"]["ip"], mac=HOST_SPECS["h_benign"]["mac"])
    h_attacker = net.addHost("h_attacker", ip=HOST_SPECS["h_attacker"]["ip"], mac=HOST_SPECS["h_attacker"]["mac"])
    h_server = net.addHost("h_server", ip=HOST_SPECS["h_server"]["ip"], mac=HOST_SPECS["h_server"]["mac"])

    net.addLink(h_benign, s1)
    net.addLink(h_attacker, s1)
    net.addLink(s1, s2)
    net.addLink(s2, h_server)

    net.start()

    # In OVS userspace (netdev) mode, Linux veth TX checksum/TSO/GSO offload leaves
    # checksums uncomputed when packets pass through AF_PACKET, causing TCP drops.
    if datapath == "user":
        for host in (h_benign, h_attacker, h_server):
            intf = host.defaultIntf().name
            host.cmd(f"ethtool -K {intf} tx off rx off sg off tso off gso off gro off 2>/dev/null || true")
        for sw in (s1, s2):
            for intf in sw.intfNames():
                if intf != "lo":
                    subprocess.run(
                        ["ethtool", "-K", intf, "tx", "off", "rx", "off", "sg", "off", "tso", "off", "gso", "off", "gro", "off"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )

    # Configure explicit software flow-table limit (TCAM proxy, NOT hardware TCAM)
    for sw in ("s1", "s2"):
        subprocess.run(
            [
                "ovs-vsctl",
                "--",
                "--id=@ft",
                "create",
                "Flow_Table",
                f"flow_limit={int(flow_table_limit)}",
                f"overflow_policy={overflow_policy}",
                "--",
                "set",
                "Bridge",
                sw,
                "flow_tables:0=@ft",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

    # Pre-populate static ARP entries between known hosts so IPv4 tests avoid ARP storms
    hosts = {"h_benign": h_benign, "h_attacker": h_attacker, "h_server": h_server}
    for name_a, host_a in hosts.items():
        for name_b, spec_b in HOST_SPECS.items():
            if name_a != name_b:
                ip_b = spec_b["ip"].split("/")[0]
                host_a.cmd(f"arp -s {ip_b} {spec_b['mac']}")

    meta = {
        "ovs_datapath": datapath,
        "flow_table_limit": int(flow_table_limit),
        "overflow_policy": overflow_policy,
        "openflow_version": openflow_version,
        "switches": ["s1", "s2"],
        "hosts": HOST_SPECS,
    }
    return net, meta


def flush_dynamic_flows(
    switches: list[str] | tuple[str, ...] = ("s1", "s2"),
    openflow_version: str = "OpenFlow13",
    dynamic_cookies: tuple[str, ...] = ("0x10/-1", "0x20/-1"),
    max_retries: int = 6,
) -> None:
    """Remove all dynamic forwarding (0x10) and mitigation (0x20) rules while preserving table-miss (0x0).

    Retries briefly if lingering Linux TCP FIN/RST retransmissions arrive during deletion,
    then strictly asserts zero remaining dynamic flows on every switch to prevent carryover.
    """
    import time

    for attempt in range(max_retries):
        all_zero = True
        remaining_map: dict[str, int] = {}
        for sw in switches:
            for cookie_mask in dynamic_cookies:
                subprocess.run(
                    ["ovs-ofctl", "-O", openflow_version, "del-flows", sw, f"cookie={cookie_mask}"],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
            rem = get_dynamic_flow_count(sw, openflow_version)
            remaining_map[sw] = rem
            if rem != 0:
                all_zero = False
        if all_zero:
            return
        if attempt < max_retries - 1:
            time.sleep(0.5)
    raise RuntimeError(f"Flow flush failed after {max_retries} attempts: {remaining_map}")


def get_dynamic_flow_count(switch_name: str, openflow_version: str = "OpenFlow13") -> int:
    """Return number of active dynamic (non-table-miss) flows on switch table 0."""
    try:
        out = subprocess.check_output(
            ["ovs-ofctl", "-O", openflow_version, "dump-flows", switch_name, "table=0"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        count = 0
        for line in out.splitlines():
            line_s = line.strip()
            if not line_s or line_s.startswith("OFPST_FLOW") or line_s.startswith("NXST_FLOW"):
                continue
            if "priority=0" in line_s and "CONTROLLER" in line_s:
                continue
            count += 1
        return count
    except Exception:
        return -1
