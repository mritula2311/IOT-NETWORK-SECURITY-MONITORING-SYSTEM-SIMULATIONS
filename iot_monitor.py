#!/usr/bin/env python3
"""Educational IoT monitor: synthetic events by default; passive capture optional."""

import argparse
import json
import math
import time
import uuid
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network


@dataclass(frozen=True)
class Config:
    # Working demo values; substitute these placeholders for YOUR lab.
    subnet: str = "192.168.50.0/24"  # [MONITORED_SUBNET]
    allowed: tuple = (              # [AUTHORIZED_IP_ADDRESSES]
        "192.168.50.1", "192.168.50.10", "192.168.50.11", "192.168.50.20"
    )
    threshold: int = 30             # [THRESHOLD_VALUE]: packets per window
    window: float = 5.0             # [WINDOW_SECONDS]
    port_threshold: int = 6         # [PORT_THRESHOLD]: distinct TCP ports
    cooldown: float = 10.0          # [ALERT_COOLDOWN_SECONDS]


@dataclass(frozen=True)
class Event:
    """Packet metadata; t is elapsed seconds, not wall-clock time."""
    t: float
    src: str
    dst: str
    protocol: str = "TCP"
    dport: int = 8883
    initial_syn: bool = False       # TCP SYN set and ACK unset


class Monitor:
    """Detection rules are independent of simulation and packet capture."""

    def __init__(self, config, emit):
        self.cfg, self.emit = config, emit
        self.network = IPv4Network(config.subnet)
        self.allowed = {str(IPv4Address(ip)) for ip in config.allowed}
        if not self.allowed or any(IPv4Address(ip) not in self.network
                                   for ip in self.allowed):
            raise ValueError("Allowlist must contain IPv4 addresses in the subnet.")
        if config.threshold < 1 or not 1 <= config.port_threshold <= 65536:
            raise ValueError("Packet threshold must be positive; ports: 1..65536.")
        if any(not math.isfinite(v) or v <= 0
               for v in (config.window, config.cooldown)):
            raise ValueError("Window and cooldown must be finite and positive.")
        self.recent = {}            # source -> recent packet times
        self.ports = {}             # (source, destination) -> port:last_seen
        self.last_alert = {}        # (rule, source, destination-or-empty) -> time
        self.counts = Counter()
        self.observed = self.monitored = 0
        self.latest = -math.inf

    def _expire(self, now):
        """Use the rolling interval (now - window, now]; remove idle state."""
        cutoff = now - self.cfg.window
        for src, times in list(self.recent.items()):
            while times and times[0] <= cutoff:
                times.popleft()
            if not times:
                del self.recent[src]
        for pair, ports in list(self.ports.items()):
            for port, seen in list(ports.items()):
                if seen <= cutoff:
                    del ports[port]
            if not ports:
                del self.ports[pair]
        for key, seen in list(self.last_alert.items()):
            if now - seen >= self.cfg.cooldown:
                del self.last_alert[key]

    def _alert(self, rule, event, detail, per_destination=False):
        # Suppress duplicate alerts without suppressing packet counting.
        key = (rule, event.src, event.dst if per_destination else "")
        if key in self.last_alert:
            return
        self.last_alert[key] = event.t
        self.counts[rule] += 1
        self.emit({"rule": rule, "elapsed_s": round(event.t, 3),
                   "source": event.src, "destination": event.dst,
                   "detail": detail})

    def process(self, event):
        """Accept ordered events; only local source addresses are in scope."""
        if not math.isfinite(event.t) or event.t < 0 or event.t < self.latest:
            raise ValueError("Event times must be finite, nonnegative and ordered.")
        self.latest = event.t
        self.observed += 1
        if IPv4Address(event.src) not in self.network:
            return  # External servers are not compared with a LOCAL allowlist.
        self.monitored += 1
        self._expire(event.t)

        if event.src not in self.allowed:
            self._alert("UNKNOWN_IP", event, "Local source is absent from allowlist.")

        # Keep only enough timestamps to decide whether the limit is exceeded.
        # This is a threshold detector, not an exact high-volume packet counter.
        if event.src not in self.recent:
            self.recent[event.src] = deque(maxlen=self.cfg.threshold + 1)
        times = self.recent[event.src]
        times.append(event.t)
        if len(times) > self.cfg.threshold:
            self._alert("TRAFFIC_BURST", event,
                        f">{self.cfg.threshold} packets in {self.cfg.window:g}s.")

        # Initial SYNs count as connection attempts; ACKs and SYN-ACKs do not.
        # Repeated attempts to the same port count as ONE distinct port.
        if event.protocol == "TCP" and event.initial_syn:
            ports = self.ports.setdefault((event.src, event.dst), {})
            ports[event.dport] = event.t
            if len(ports) >= self.cfg.port_threshold:
                self._alert("PORT_SCAN_PATTERN", event,
                            f"{len(ports)} distinct TCP destination ports in "
                            f"{self.cfg.window:g}s.", per_destination=True)


def simulate(scenario):
    """Return metadata only. No sockets, network sends, scanning or exploits."""
    dst = "192.168.50.20"
    normal = [Event(float(i), f"192.168.50.{10 + i % 2}", dst)
              for i in range(20)]
    unknown = [Event(25 + i * 0.1, "192.168.50.99", dst) for i in range(2)]
    burst = [Event(30 + i * 0.05, "192.168.50.10", dst) for i in range(40)]
    scan = [Event(40 + i * 0.1, "192.168.50.11", dst,
                  dport=2000 + i, initial_syn=True) for i in range(6)]
    scenarios = {"normal": normal, "unknown": unknown,
                 "burst": burst, "scan": scan,
                 "mixed": normal + unknown + burst + scan}
    return iter(scenarios[scenario])


def packet_to_event(packet, elapsed):
    """Optional adapter: extract outer IPv4 metadata; do not store payloads."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    # Walk through Ethernet/VLAN layers, but do not inspect IPv6 tunnels.
    layer = packet
    while layer and not isinstance(layer, (IP, IPv6)):
        layer = layer.payload
    if not isinstance(layer, IP):
        return None
    transport = layer.payload
    protocol, port, syn = "OTHER", 0, False
    if int(layer.frag) == 0 and isinstance(transport, TCP):
        flags = int(transport.flags)
        protocol, port = "TCP", int(transport.dport)
        syn = bool(flags & 0x02) and not bool(flags & 0x10)
    elif int(layer.frag) == 0 and isinstance(transport, UDP):
        protocol, port = "UDP", int(transport.dport)
    return Event(elapsed, layer.src, layer.dst, protocol, port, syn)


def capture(monitor, interface, duration):
    """Passively observe one interface for a finite time. Never send packets."""
    from scapy.all import sniff
    from scapy.error import Scapy_Exception

    start = time.monotonic()  # Clock adjustments cannot break rolling windows.

    def handle(packet):
        event = packet_to_event(packet, time.monotonic() - start)
        if event is not None:
            monitor.process(event)

    # No BPF filter: avoids a filter-compilation dependency on some platforms.
    # store=False prevents Scapy from accumulating a list of captured packets.
    try:
        sniff(iface=interface, prn=handle, store=False, timeout=duration)
    except Scapy_Exception as exc:
        raise OSError(f"Capture failed: {exc}") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("simulate", "live"), default="simulate")
    parser.add_argument("--scenario", default="mixed",
                        choices=("normal", "unknown", "burst", "scan", "mixed"))
    parser.add_argument("--interface", default="[NETWORK_INTERFACE]")
    parser.add_argument("--subnet", default=Config.subnet)
    parser.add_argument("--allow", nargs="+", default=Config.allowed)
    parser.add_argument("--threshold", type=int, default=Config.threshold)
    parser.add_argument("--window", type=float, default=Config.window)
    parser.add_argument("--port-threshold", type=int, default=Config.port_threshold)
    parser.add_argument("--cooldown", type=float, default=Config.cooldown)
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--log", default="alerts.jsonl")
    args = parser.parse_args()
    if not math.isfinite(args.duration) or args.duration <= 0:
        parser.error("Duration must be finite and positive.")
    if args.mode == "live" and (not args.interface or "[" in args.interface):
        parser.error("Replace [NETWORK_INTERFACE] with a Scapy interface name.")

    config = Config(args.subnet, tuple(args.allow), args.threshold,
                    args.window, args.port_threshold, args.cooldown)
    run_id = uuid.uuid4().hex[:12]
    started = datetime.now(timezone.utc).isoformat()
    try:
        # Append preserves earlier runs; run_id separates their alert records.
        with open(args.log, "a", encoding="utf-8") as log:
            def emit(alert):
                record = {"type": "alert", "run_id": run_id,
                          "mode": args.mode, "run_started_utc": started, **alert}
                line = json.dumps(record, sort_keys=True)
                log.write(line + "\n")
                log.flush()
                print(line)

            monitor = Monitor(config, emit)
            try:
                if args.mode == "simulate":
                    for event in simulate(args.scenario):
                        monitor.process(event)
                else:
                    capture(monitor, args.interface, args.duration)
            except KeyboardInterrupt:
                print("Stopped by user.")
            print(json.dumps({"type": "summary", "run_id": run_id,
                              "observed_ipv4": monitor.observed,
                              "monitored_local": monitor.monitored,
                              "alerts": dict(monitor.counts)}, sort_keys=True))
    except ImportError:
        parser.exit(1, "Live capture requires Scapy: python -m pip install scapy\n")
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Configuration, log or capture error: {exc}\n")


if __name__ == "__main__":
    main()
