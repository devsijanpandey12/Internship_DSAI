"""Minimal smoke test: verifies OVS startup, os-ken OpenFlow 1.3 handshake, and Mininet pingAll."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from topology.minimal_topology import build_minimal_network, get_dynamic_flow_count  # noqa: E402


def main() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    ctrl = subprocess.Popen(
        [
            "osken-manager",
            "--ofp-tcp-listen-port",
            "6653",
            str(REPO_ROOT / "src" / "controller" / "baseline_controller.py"),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    net = None
    try:
        time.sleep(2.5)
        if ctrl.poll() is not None:
            out, _ = ctrl.communicate(timeout=2)
            raise RuntimeError(f"osken-manager exited early (rc={ctrl.returncode}):\n{out}")

        net, meta = build_minimal_network(flow_table_limit=4096)
        time.sleep(1.5)
        loss = float(net.pingAll(timeout="2"))
        f1 = get_dynamic_flow_count("s1")
        f2 = get_dynamic_flow_count("s2")
        print(
            f"SMOKE_TEST_OK: datapath={meta['ovs_datapath']}, "
            f"pingAll_loss={loss:.2f}%, s1_flows={f1}, s2_flows={f2}",
            flush=True,
        )
        assert loss == 0.0, f"Expected 0% loss, got {loss}%"
        assert f1 > 0 and f2 > 0, f"Expected dynamic flows installed, got s1={f1}, s2={f2}"
    finally:
        if net is not None:
            net.stop()
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ctrl.terminate()
        try:
            ctrl.wait(timeout=5)
        except Exception:
            ctrl.kill()


if __name__ == "__main__":
    main()
