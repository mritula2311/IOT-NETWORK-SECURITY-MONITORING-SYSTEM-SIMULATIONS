#!/usr/bin/env python3
"""Enhanced IoT monitor with per-device thresholds and explainable alerts."""

import json
import math
import uuid
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from iot_monitor import Event
from src.device_registry import DeviceRegistry


# Severity weights and scores for detection rules
RULE_SEVERITY = {
    "UNKNOWN_IP": ("HIGH", 35),
    "UNAUTHORIZED_SERVICE": ("HIGH", 35),
    "TRAFFIC_BURST": ("MEDIUM", 25),
    "PORT_SCAN_PATTERN": ("CRITICAL", 50),
}


class EnhancedMonitor:
    """Detection & Prevention engine with per-device thresholds,
    service whitelisting, threat scoring, and automated IPS quarantine.
    """

    def __init__(self, registry, subnet, window=5.0, port_threshold=6,
                 cooldown=10.0, emit=None, quarantine_threshold=None):
        self.registry = registry
        self.network = IPv4Network(subnet)
        self.allowed = registry.get_allowed_ips()
        self.window = window
        self.port_threshold = port_threshold
        self.cooldown = cooldown
        self.quarantine_threshold = (
            quarantine_threshold if quarantine_threshold is not None
            else getattr(registry, "quarantine_threat_threshold", 60)
        )
        self.emit = emit or (lambda x: None)

        # Validate
        if any(IPv4Address(ip) not in self.network for ip in self.allowed):
            raise ValueError("All registered IPs must be within the monitored subnet.")
        if not 1 <= port_threshold <= 65536:
            raise ValueError("Port threshold must be between 1 and 65536.")
        if any(not math.isfinite(v) or v <= 0 for v in (window, cooldown)):
            raise ValueError("Window and cooldown must be finite and positive.")

        # State
        self.recent = {}            # source -> deque of timestamps
        self.ports = {}             # (source, dest) -> {port: last_seen}
        self.last_alert = {}        # (rule, source, dest_or_empty) -> time
        self.counts = Counter()
        self.alerts_log = []        # All alert records for evaluation
        self.threat_scores = {}     # source -> threat score (0-100)
        self.quarantined = {}       # source -> quarantine record
        self.mitigations = []       # list of firewall isolation actions
        self.blocked_packets = 0    # packets dropped post-quarantine
        self.observed = self.monitored = 0
        self.latest = -math.inf

    def _expire(self, now):
        """Remove expired state from rolling windows."""
        cutoff = now - self.window
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
            if now - seen >= self.cooldown:
                del self.last_alert[key]

    def _get_threat_tier(self, score):
        """Map numeric threat score to security assessment tier."""
        if score <= 0:
            return "SECURE"
        elif score < 40:
            return "ELEVATED"
        elif score < 70:
            return "SUSPICIOUS"
        return "COMPROMISED"

    def _alert(self, rule, event, detail, per_destination=False):
        """Emit an explainable alert with threat score and active defense response."""
        key = (rule, event.src, event.dst if per_destination else "")
        if key in self.last_alert:
            return
        self.last_alert[key] = event.t
        self.counts[rule] += 1

        severity, weight = RULE_SEVERITY.get(rule, ("MEDIUM", 20))

        # Update threat score
        current_score = self.threat_scores.get(event.src, 0)
        new_score = min(100, current_score + weight)
        self.threat_scores[event.src] = new_score

        profile = self.registry.get_profile(event.src)

        # Automated Quarantine / Active Defense check
        if (new_score >= self.quarantine_threshold or severity == "CRITICAL") and event.src not in self.quarantined:
            quarantine_action = {
                "ip": event.src,
                "device_name": profile.name if profile else "UNREGISTERED",
                "timestamp": round(event.t, 3),
                "threat_score": new_score,
                "trigger_rule": rule,
                "status": "QUARANTINED",
                "firewall_rule": f"iptables -I FORWARD -s {event.src} -j DROP",
                "action": "AUTOMATED_ISOLATION",
            }
            self.quarantined[event.src] = quarantine_action
            self.mitigations.append(quarantine_action)

        alert = {
            "rule": rule,
            "severity": severity,
            "threat_score": new_score,
            "threat_tier": self._get_threat_tier(new_score),
            "elapsed_s": round(event.t, 3),
            "source": event.src,
            "destination": event.dst,
            "dport": event.dport,
            "detail": detail,
            "device_name": profile.name if profile else "UNREGISTERED",
            "device_role": profile.role if profile else "unknown",
            "threshold_used": (
                profile.threshold if profile else self.registry.default_threshold
            ),
            "quarantined": event.src in self.quarantined,
        }
        self.alerts_log.append(alert)
        self.emit(alert)

    def process(self, event):
        """Process a single event through all detection rules and IPS enforcement."""
        if not math.isfinite(event.t) or event.t < 0 or event.t < self.latest:
            raise ValueError("Event times must be finite, nonnegative and ordered.")
        self.latest = event.t
        self.observed += 1

        if IPv4Address(event.src) not in self.network:
            return  # External source — out of scope
        self.monitored += 1

        # Active IPS check: drop packet if source is already quarantined
        if event.src in self.quarantined:
            self.blocked_packets += 1
            return

        self._expire(event.t)

        # Rule 1: Unknown IP check
        if event.src not in self.allowed:
            self._alert("UNKNOWN_IP", event,
                         "Local source is absent from device registry.")

        # Rule 2: Unauthorized port / service check (Zero-Trust profile enforcement)
        if event.src in self.allowed and not self.registry.is_port_allowed(event.src, event.dport):
            self._alert("UNAUTHORIZED_SERVICE", event,
                         f"Traffic to destination port {event.dport} violates allowed service profile.")

        # Rule 3: Traffic burst (per-device threshold)
        device_threshold = self.registry.get_threshold(event.src)
        if event.src not in self.recent:
            self.recent[event.src] = deque(maxlen=device_threshold + 1)
        times = self.recent[event.src]
        times.append(event.t)
        if len(times) > device_threshold:
            self._alert("TRAFFIC_BURST", event,
                         f">{device_threshold} packets in {self.window:g}s "
                         f"(device threshold={device_threshold}).")

        # Rule 4: Port scan pattern
        if event.protocol == "TCP" and event.initial_syn:
            ports = self.ports.setdefault((event.src, event.dst), {})
            ports[event.dport] = event.t
            if len(ports) >= self.port_threshold:
                self._alert("PORT_SCAN_PATTERN", event,
                             f"{len(ports)} distinct TCP destination ports in "
                             f"{self.window:g}s.", per_destination=True)

    def get_summary(self):
        """Return a summary dict of the monitoring run."""
        return {
            "observed_ipv4": self.observed,
            "monitored_local": self.monitored,
            "blocked_packets": self.blocked_packets,
            "alerts": dict(self.counts),
            "total_alerts": sum(self.counts.values()),
            "threat_scores": dict(self.threat_scores),
            "quarantined_devices": list(self.quarantined.values()),
            "mitigations": list(self.mitigations),
        }
