"""Isolated laboratory traffic generators and benign connection-setup probes.

For authorized, isolated Mininet testbeds only.
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import struct
import threading
import time

from evaluation.metrics import summarize_distribution


def ipv4_checksum(header: bytes) -> int:
    """Compute RFC 791 one's-complement checksum for an IPv4 header."""
    if len(header) % 2 == 1:
        header += b"\x00"
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def build_spoofed_udp_frame(
    src_mac: bytes,
    dst_mac: bytes,
    src_ip_int: int,
    dst_ip_int: int,
    src_port: int,
    dst_port: int,
    payload: bytes,
    ip_id: int = 0,
) -> bytes:
    """Build a valid Ethernet + IPv4 + UDP raw frame without Scapy loop overhead."""
    udp_len = 8 + len(payload)
    ip_total_len = 20 + udp_len

    eth_hdr = dst_mac + src_mac + b"\x08\x00"
    ip_hdr_no_csum = struct.pack(
        "!BBHHHBBHII",
        0x45,
        0,
        ip_total_len,
        ip_id & 0xFFFF,
        0x4000,  # Don't Fragment
        64,
        17,  # UDP
        0,
        src_ip_int,
        dst_ip_int,
    )
    csum = ipv4_checksum(ip_hdr_no_csum)
    ip_hdr = ip_hdr_no_csum[:10] + struct.pack("!H", csum) + ip_hdr_no_csum[12:]
    # UDP checksum=0 is valid under IPv4 (RFC 768) and avoids per-packet payload hashing
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    return eth_hdr + ip_hdr + udp_hdr + payload


def run_spoof_udp(args: argparse.Namespace) -> None:
    """Send paced spoofed-source-IP/port UDP packets on an isolated Mininet interface."""
    rng = random.Random(args.seed)
    src_mac = mac_to_bytes(args.src_mac)
    dst_mac = mac_to_bytes(args.dst_mac)
    dst_ip_int = struct.unpack("!I", socket.inet_aton(args.dst_ip))[0]
    base_src_net = struct.unpack("!I", socket.inet_aton("10.1.0.0"))[0]
    payload = b"A" * args.payload_bytes

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.iface, 0))

    rate_pps = float(args.rate_pps)
    duration_s = float(args.duration)
    interval_s = 1.0 / rate_pps if rate_pps > 0 else 0.0

    start = time.perf_counter()
    end = start + duration_s
    next_send = start
    sent = 0
    overruns = 0

    try:
        while True:
            now = time.perf_counter()
            if now >= end:
                break
            if now < next_send:
                sleep_for = next_send - now
                if sleep_for > 0.0005:
                    time.sleep(sleep_for - 0.0003)
                continue

            if now - next_send > max(0.01, interval_s * 5):
                overruns += 1
                next_send = now

            src_ip_int = base_src_net | rng.randint(1, 65534)
            src_port = rng.randint(1024, 65535)
            frame = build_spoofed_udp_frame(
                src_mac=src_mac,
                dst_mac=dst_mac,
                src_ip_int=src_ip_int,
                dst_ip_int=dst_ip_int,
                src_port=src_port,
                dst_port=args.dst_port,
                payload=payload,
                ip_id=sent,
            )
            sock.send(frame)
            sent += 1
            next_send += interval_s
    finally:
        sock.close()

    elapsed = max(time.perf_counter() - start, 1e-9)
    print(
        json.dumps(
            {
                "mode": "spoof_udp",
                "target_pps": rate_pps,
                "duration_s": elapsed,
                "sent_packets": sent,
                "achieved_pps": sent / elapsed,
                "pacing_overruns": overruns,
            }
        ),
        flush=True,
    )


def run_echo_server(args: argparse.Namespace) -> None:
    """Lightweight multi-threaded TCP echo server for benign new-flow setup probes."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(512)

    def _handle(conn: socket.socket) -> None:
        try:
            conn.settimeout(2.0)
            data = conn.recv(64)
            if data:
                conn.sendall(data)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    try:
        while True:
            conn, _ = srv.accept()
            t = threading.Thread(target=_handle, args=(conn,), daemon=True)
            t.start()
    finally:
        srv.close()


def run_new_flow_probe(args: argparse.Namespace) -> None:
    """Open fresh TCP connections periodically to measure new-flow control-plane setup QoS."""
    interval_s = 1.0 / float(args.rate_hz)
    start = time.perf_counter()
    end = start + float(args.duration)
    next_probe = start

    latencies_ms: list[float] = []
    attempts = 0
    successes = 0
    failures = 0

    while True:
        now = time.perf_counter()
        if now >= end:
            break
        if now < next_probe:
            time.sleep(min(next_probe - now, 0.05))
            continue

        attempts += 1
        t0 = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(args.timeout))
        try:
            sock.connect((args.dst_ip, args.dst_port))
            sock.sendall(b"KU_DSAI_PROBE_01")
            resp = sock.recv(64)
            if resp == b"KU_DSAI_PROBE_01":
                latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                successes += 1
            else:
                failures += 1
        except Exception:
            failures += 1
        finally:
            try:
                sock.close()
            except Exception:
                pass
        next_probe += interval_s

    print(
        json.dumps(
            {
                "mode": "new_flow_probe",
                "attempts": attempts,
                "successes": successes,
                "failures": failures,
                "success_rate_pct": (100.0 * successes / attempts) if attempts else 0.0,
                "setup_latency_ms": summarize_distribution(latencies_ms),
                "raw_setup_latency_ms": latencies_ms,
            }
        ),
        flush=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Isolated Mininet traffic generator & probe")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_udp = sub.add_parser("spoof_udp")
    p_udp.add_argument("--iface", required=True)
    p_udp.add_argument("--src-mac", required=True)
    p_udp.add_argument("--dst-mac", required=True)
    p_udp.add_argument("--dst-ip", required=True)
    p_udp.add_argument("--dst-port", type=int, default=9999)
    p_udp.add_argument("--rate-pps", type=float, required=True)
    p_udp.add_argument("--duration", type=float, required=True)
    p_udp.add_argument("--payload-bytes", type=int, default=64)
    p_udp.add_argument("--seed", type=int, default=42)

    p_srv = sub.add_parser("echo_server")
    p_srv.add_argument("--bind", default="0.0.0.0")
    p_srv.add_argument("--port", type=int, default=8088)

    p_probe = sub.add_parser("new_flow_probe")
    p_probe.add_argument("--dst-ip", required=True)
    p_probe.add_argument("--dst-port", type=int, default=8088)
    p_probe.add_argument("--rate-hz", type=float, default=2.0)
    p_probe.add_argument("--duration", type=float, required=True)
    p_probe.add_argument("--timeout", type=float, default=2.0)

    args = parser.parse_args()
    if args.cmd == "spoof_udp":
        run_spoof_udp(args)
    elif args.cmd == "echo_server":
        run_echo_server(args)
    elif args.cmd == "new_flow_probe":
        run_new_flow_probe(args)


if __name__ == "__main__":
    main()
