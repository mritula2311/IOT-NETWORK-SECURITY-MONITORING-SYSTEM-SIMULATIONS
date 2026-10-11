#!/usr/bin/env python3
"""Device registry: maps IP addresses to device roles and per-device thresholds."""

import json
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from pathlib import Path


@dataclass(frozen=True)
class DeviceProfile:
    """A single registered IoT device with its role-specific threshold and allowed ports."""
    ip: str
    name: str
    role: str
    threshold: int
    allowed_ports: tuple = ()
    description: str = ""


class DeviceRegistry:
    """Load device policies from JSON and provide per-device threshold lookups.

    If a device IP is registered, its individual threshold is used.
    If a device IP is in the subnet but NOT registered, it's flagged as unknown.
    """

    def __init__(self, policy_path):
        self.devices = {}          # ip -> DeviceProfile
        self.default_threshold = 30
        self.quarantine_threat_threshold = 60
        self._load(policy_path)

    def _load(self, policy_path):
        """Load device registry from a JSON policy file."""
        path = Path(policy_path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {policy_path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.default_threshold = data.get("default_threshold", 30)
        self.quarantine_threat_threshold = data.get("quarantine_threat_threshold", 60)

        for device in data.get("devices", []):
            ip = str(IPv4Address(device["ip"]))  # Validate IP format
            allowed = tuple(device.get("allowed_ports", []))
            profile = DeviceProfile(
                ip=ip,
                name=device["name"],
                role=device["role"],
                threshold=device["threshold"],
                allowed_ports=allowed,
                description=device.get("description", "")
            )
            self.devices[ip] = profile

    def is_registered(self, ip):
        """Check if an IP address is in the device registry."""
        return str(ip) in self.devices

    def get_profile(self, ip):
        """Return the DeviceProfile for a registered IP, or None."""
        return self.devices.get(str(ip))

    def is_port_allowed(self, ip, dport):
        """Check if destination port is permitted for this device.
        If no allowed_ports specified, all ports are permitted.
        """
        profile = self.get_profile(str(ip))
        if not profile or not profile.allowed_ports:
            return True
        return dport in profile.allowed_ports

    def get_threshold(self, ip):
        """Return per-device threshold if registered, else default."""
        profile = self.get_profile(str(ip))
        return profile.threshold if profile else self.default_threshold

    def get_allowed_ips(self):
        """Return the set of all registered IP addresses."""
        return set(self.devices.keys())

    def summary(self):
        """Return a human-readable summary of the registry."""
        lines = [f"Device Registry ({len(self.devices)} devices):"]
        for ip, dev in sorted(self.devices.items()):
            lines.append(
                f"  {dev.name:20s} | {ip:16s} | role={dev.role:8s} | "
                f"threshold={dev.threshold}"
            )
        lines.append(f"  Default threshold for unregistered: {self.default_threshold}")
        return "\n".join(lines)
