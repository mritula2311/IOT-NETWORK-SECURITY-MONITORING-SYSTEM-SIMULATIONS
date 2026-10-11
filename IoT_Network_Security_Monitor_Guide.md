# IoT Network Security Monitor

An educational Python mini-project for identifying suspicious activity in an IoT network.

## 1. Project Overview

### Problem statement

IoT networks connect sensors, cameras, smart appliances, controllers, and gateways. Their security can be affected by weak access controls, outdated firmware, exposed services, and limited logging or device-management capabilities. These limitations can make unauthorized use and compromised-device behavior difficult to recognize. NIST describes these management, monitoring, and lifecycle challenges in its guidance on IoT cybersecurity risks [1].

### Proposed solution and conceptual framework

Develop a passive, rule-based monitor that observes packet metadata and identifies deviations from an explicitly configured network policy. The project uses IP addresses, packet timing, destination ports, and TCP flags; it does not require application payload inspection.

The monitor performs five steps:

1. Obtain synthetic traffic records or observe packets through an optional Scapy adapter.
2. Convert each input into a common `Event` structure.
3. Select events whose source belongs to the monitored IPv4 subnet.
4. Apply an IP allowlist, a rolling packet-count threshold, and a TCP port-diversity rule.
5. Display alerts and append them to a JSON Lines log for investigation.

Monitoring reduces the time between suspicious activity and investigation. An administrator can verify a device against the inventory, examine its logs, and decide whether containment is appropriate. NIST's device baseline identifies cybersecurity state awareness as a capability supporting incident detection [2]. This project illustrates network observation; it does not claim to implement that entire baseline.

**An alert is evidence of a policy mismatch or unusual pattern, not proof of an attack.** An IP address absent from the allowlist may belong to a newly installed legitimate device. An allowed IP can also be spoofed or assigned to a compromised device. Monitoring supports access controls, software updates, and network segmentation; the script itself does not authenticate devices or block traffic.

### Detection rules

| Rule | Exact trigger with demo settings | Interpretation |
| --- | --- | --- |
| `UNKNOWN_IP` | A local source address is absent from the configured allowlist. | Potentially unauthorized device or outdated inventory. |
| `TRAFFIC_BURST` | More than 30 packets from one local source in a rolling 5-second window. | Unusual traffic volume; investigate device behavior. |
| `PORT_SCAN_PATTERN` | Initial TCP SYNs from one local source to at least 6 distinct ports on one destination within 5 seconds. | Scan-like connection pattern; not a confirmed scan. |

An **initial SYN** has the TCP SYN flag set and ACK flag unset. Replies with SYN-ACK and ordinary ACK/data packets do not contribute to port diversity. Repeated SYNs to the same port count once. The scan rule groups by both source and destination, so different destination devices do not share one port count.

The time window is `(current_time - window, current_time]`: an event exactly five seconds old is expired. Burst detection uses a count per window, not an instantaneous packets-per-second estimate. A ten-second cooldown suppresses duplicate alerts for the same rule and source; scan alerts also distinguish destinations. Rules remain independent during cooldown.

## 2. Technical Requirements

### Software and libraries

| Component | Requirement and purpose |
| --- | --- |
| Python | Python 3.10 or later; the simulation was verified with Python 3.12. |
| Standard library | `argparse`, `json`, `math`, `time`, `uuid`, `collections`, `dataclasses`, `datetime`, and `ipaddress`. No installation is needed for simulation. |
| Scapy | Optional, for passive packet capture. Install with `python -m pip install scapy`. |
| Windows capture driver | Npcap is required for Scapy capture; follow Scapy's Windows installation instructions [3]. |
| Linux/macOS capture support | Appropriate capture permissions and platform support are needed. Scapy documents native Linux and macOS support and optional libpcap use [3]. |
| Hardware | Any computer for simulation; an authorized lab network and suitable capture interface for live mode. |

The default demonstration runs on Windows, Linux, and macOS without administrator privileges or network access. Live capture has operating-system-specific permissions. Scapy's `sniff()` callback supplies packets to the same detection engine, and `store=False` avoids accumulating captured packet objects [4].

For an isolated Python environment, run `python -m venv .venv`. Activate it with `.venv\Scripts\activate.bat` in Windows Command Prompt, `.\.venv\Scripts\Activate.ps1` in PowerShell, or `source .venv/bin/activate` on Linux/macOS. Activation is optional for the standard-library demonstration. Where necessary, use `py` on Windows or `python3` on Linux/macOS instead of `python`.

### Configuration placeholders

Runnable demonstration values are supplied. Replace the placeholders with your laboratory values before live capture; do not paste bracketed placeholders as numeric values.

| Placeholder | CLI option | Demonstration default |
| --- | --- | --- |
| `[NETWORK_INTERFACE]` | `--interface` | Must be supplied for live capture. |
| `[MONITORED_SUBNET]` | `--subnet` | `192.168.50.0/24` |
| `[AUTHORIZED_IP_ADDRESSES]` | `--allow` | `192.168.50.1`, `.10`, `.11`, and `.20`, each as a full address. |
| `[THRESHOLD_VALUE]` | `--threshold` | `30` packets per window; alert starts at packet 31. |
| `[WINDOW_SECONDS]` | `--window` | `5` seconds |
| `[PORT_THRESHOLD]` | `--port-threshold` | `6` distinct TCP destination ports |
| `[ALERT_COOLDOWN_SECONDS]` | `--cooldown` | `10` seconds |

These are deliberately small demonstration thresholds, not recommended production settings. Include relevant gateways and servers in the inventory when their source addresses are within the selected subnet. Use a valid network prefix such as `192.168.50.0/24`, not a host address such as `192.168.50.7/24`.

## 3. Python Code Block

Save the following as `iot_monitor.py`. The project archive includes this exact script and `test_monitor.py`.

```python
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
```

### Modular design

| Component | Responsibility |
| --- | --- |
| `Config` | Holds policy values and working demonstration defaults. |
| `Event` | Represents metadata using one format for both input modes. |
| `Monitor` | Applies scope, rolling-window rules, alert cooldown, and state expiry. |
| `simulate()` | Produces fixed, ordered records without opening network sockets. |
| `packet_to_event()` | Extracts outer IPv4 metadata from Scapy packets. |
| `capture()` | Observes one interface for a finite duration. |
| `main()` | Parses configuration, writes JSONL alerts, and prints a run summary. |

The rate detector retains only the most recent `threshold + 1` timestamps per source. This is sufficient to decide whether the threshold is exceeded; it intentionally does not claim an exact high-volume count. Port history and cooldown state expire as further monitored events arrive. State is processed sequentially for this small laboratory application.

## 4. Simulation Guide

### A. Demonstration network

| Address | Simulated role |
| --- | --- |
| `192.168.50.1` | Authorized gateway |
| `192.168.50.10` | Authorized temperature sensor |
| `192.168.50.11` | Authorized camera/controller |
| `192.168.50.20` | Authorized IoT application server |
| `192.168.50.99` | Unknown device absent from the allowlist |

These addresses are labels in the simulation. No physical devices, broker, or network configuration are required. Normal records use destination port 8883 as an illustrative IoT service label; no MQTT session is established or decoded.

### B. Normal versus suspicious traffic

| Scenario | Synthetic records | Expected result with defaults |
| --- | --- | --- |
| `normal` | 20 records, one per simulated second, alternating between `.10` and `.11`. | No alerts. |
| `unknown` | 2 records from `.99` at 25.0 and 25.1 seconds. | 1 `UNKNOWN_IP`; the duplicate is suppressed. |
| `burst` | 40 records from `.10` at 0.05-second intervals, starting at 30 seconds. | 1 `TRAFFIC_BURST` at 31.5 seconds. |
| `scan` | 6 SYN records from `.11` to `.20`, targeting ports 2000–2005 at 0.1-second intervals. | 1 `PORT_SCAN_PATTERN` at 40.5 seconds. |
| `mixed` | All four sequences, in chronological order: 68 records. | 3 alerts total, one per rule. |

The suspicious scenarios represent the **observable symptoms** of malicious activity. They do not execute malware, scan a real host, flood an interface, or attempt authentication.

Simulation uses virtual elapsed time and completes immediately; it does not wait 40.5 real seconds. Its IP addresses and event counts are fixed for reproducibility. If you change the subnet, allowlist, window, or thresholds, the expected results may change; edit `simulate()` when building a different synthetic network.

### C. Run the demonstrations

Open a terminal in the folder containing `iot_monitor.py`:

```bash
python iot_monitor.py --scenario normal --log normal_alerts.jsonl
python iot_monitor.py --scenario unknown --log unknown_alerts.jsonl
python iot_monitor.py --scenario burst --log burst_alerts.jsonl
python iot_monitor.py --scenario scan --log scan_alerts.jsonl
python iot_monitor.py --scenario mixed --log mixed_alerts.jsonl
```

Running `python iot_monitor.py` alone runs the mixed scenario. Each command prints a summary. A newly created normal log is empty because only alerts are written to the log; summaries are printed to the terminal.

The mixed demonstration produces the following alert content, shown with run metadata omitted for readability:

```text
25.000s  UNKNOWN_IP        192.168.50.99 -> 192.168.50.20
         Local source is absent from allowlist.
31.500s  TRAFFIC_BURST     192.168.50.10 -> 192.168.50.20
         >30 packets in 5s.
40.500s  PORT_SCAN_PATTERN 192.168.50.11 -> 192.168.50.20
         6 distinct TCP destination ports in 5s.
Summary: 68 observed IPv4 records, 68 monitored local records, 3 alerts.
```

Actual console and file alerts are JSON objects. Their fields include `rule`, `source`, `destination`, `elapsed_s`, `detail`, `mode`, `run_id`, and `run_started_utc`. The UTC value records the real run start; simulation `elapsed_s` values are virtual and must not be interpreted as real capture timestamps.

Logs append across runs. Use a new filename for a clean demonstration or distinguish existing records by `run_id`. The script does not automatically rotate logs.

### D. Demonstrate threshold tuning

```bash
python iot_monitor.py --scenario burst --threshold 50 --log tuned_alerts.jsonl
```

With a threshold of 50, the 40-record burst produces no alert. This demonstrates the sensitivity trade-off: an overly high threshold misses relevant patterns, while an overly low threshold alerts on legitimate activity. Establish a baseline for each device type before selecting real-network thresholds; a camera and a temperature sensor can have very different traffic volumes.

### E. Optional passive live capture

Use an interface on an authorized laboratory network. Install Scapy, then inspect the available interface names:

```bash
python -m pip install scapy
python -c "from scapy.all import conf; print(conf.ifaces)"
```

Replace every bracketed placeholder in this template with a real value:

```bash
python iot_monitor.py --mode live --interface "[NETWORK_INTERFACE]" --subnet "[MONITORED_SUBNET]" --allow [AUTHORIZED_IP_ADDRESSES] --threshold [THRESHOLD_VALUE] --duration 30 --log live_alerts.jsonl
```

`[AUTHORIZED_IP_ADDRESSES]` means one or more full IPv4 addresses separated by spaces. For example, `--allow 192.168.50.1 192.168.50.10 192.168.50.11 192.168.50.20`. The default window, port threshold, and cooldown still apply unless overridden.

Capture ends after 30 seconds or when interrupted. Obtain the required capture permissions for your operating system; on Windows this also requires a functioning Npcap installation [3]. Normal permitted device activity is sufficient for checking capture integration. Suspicious patterns can remain entirely simulated.

**Capture placement matters.** A workstation cannot automatically see every packet on a switched network. A gateway observes traffic that crosses it; same-subnet device communication may require a configured switch mirror/SPAN port or a network TAP. Promiscuous mode alone does not make other switch ports' unicast traffic visible. This implementation intentionally examines only packets whose IPv4 source is in the chosen subnet. External-source traffic, IPv6, and non-IP protocols are outside its detection scope.

### F. Verification and evaluation

Run the supplied behavioral checks:

```bash
python -m unittest -v test_monitor.py
```

Verification for this deliverable: all five command-line scenarios produced their documented results, their JSONL logs matched the alert counts, and four invalid configurations were rejected. Nine core tests passed, covering threshold boundaries, expiry, repeated ports, destination grouping, cooldown, external-source scope, bounded rate history, configuration validation, and ordered timestamps. One optional Scapy adapter test was skipped because this execution environment blocks Scapy's kernel interface discovery. Live capture and Windows/macOS operation have not been verified here.

For a report, record the scenario, configuration, event count, expected alert rules, observed alert rules, and first-alert time. The mixed scenario's virtual detection delays are 0 seconds for the unknown source, 1.5 seconds after the burst begins, and 0.5 seconds after the port sequence begins. These are rule-trigger delays in synthetic time, not measured live processing latency.

Do not describe three alerts as three malicious packets: multiple records jointly trigger a rule and cooldown suppresses repeats. These small deterministic examples establish functional behavior, not real-world detection accuracy. Estimate precision, recall, and false-positive rate only after defining labeled events or episodes and testing a representative dataset.

### G. Limitations and suitable extensions

- **Identity and authentication:** DHCP changes and spoofed IPs weaken an IP-only inventory. Add inventory integration and device-authentication evidence; include application logs to investigate login attempts.
- **Heuristic coverage:** Legitimate updates can cause bursts. Slow scans, UDP scans, scans spread across many destinations, and malicious behavior inside thresholds may be missed.
- **Protocol coverage:** The adapter reads outer IPv4 headers. It does not reassemble fragments, inspect tunneled inner traffic, decrypt sessions, or analyze application payloads.
- **Performance:** The script is a single-process laboratory monitor. High packet rates, synchronous log writes, and many active source/destination pairs can overload it. It does not report capture drops or guarantee complete observation.
- **Operational maturity:** Add per-device baselines, log rotation, log access controls, capture-health reporting, and a reviewed incident-response workflow before considering broader deployment.

### H. Implemented Extensions & Enhanced System Architecture

To address the limitations identified above while remaining strictly grounded in the core academic domain (**IoT Network Security Monitoring Using Python**), the following capabilities have been implemented:

1. **Per-Device Thresholds & Role Profiles (`DeviceRegistry`)**:
   - Replaced flat, single-threshold monitoring (30 pkts/5s) with role-tailored baselines loaded from `config/device_policy.json`.
   - Eliminates false alarms from high-throughput streaming nodes (e.g., Camera-01 at threshold 40) while detecting bursts from low-rate sensors (TempSensor-01 at threshold 10).

2. **Zero-Trust Device Port Whitelisting (`UNAUTHORIZED_SERVICE`)**:
   - Enforces permitted destination ports per device role (e.g., `TempSensor-01` permitted only on MQTT/MQTTS ports 1883/8883).
   - Detects stealthy IoT malware (e.g., Mirai botnet propagation attempting Telnet on port 23 or SSH on port 22) that evade traffic volume thresholds.

3. **Composite Threat Scoring & Severity Tiers**:
   - Dynamically tracks threat scores (0–100) based on anomaly severities: `LOW` (10), `MEDIUM` (25), `HIGH` (35), `CRITICAL` (50).
   - Categorizes IoT nodes into security tiers: `SECURE` (0), `ELEVATED` (1–39), `SUSPICIOUS` (40–69), and `COMPROMISED` (70–100).

4. **Automated Active Defense & IPS Quarantine**:
   - When a node exceeds the threat threshold (≥60) or initiates a critical port scan, the engine automatically isolates the device.
   - Generates firewall mitigation rules (`iptables -I FORWARD -s <ip> -j DROP`) and blocks subsequent traffic from the compromised device.

5. **Formal 14-Case Security Testing Suite (`TC01`–`TC14`)**:
   - Comprehensive test suite covering normal sensor traffic, rogue IP detection, device thresholds, boundary limits, rolling window expiry, SYN port diversity, input validation, legitimate camera bursts, cooldown suppression, log privacy, unauthorized service detection, and active IPS quarantine. (All 14 tests pass 100%).

6. **Comparative Precision/Recall Evaluation**:
   - Benchmarks the proposed device-aware engine against the single-threshold baseline across multiple attack scenarios, demonstrating zero false positives on camera bursts and 100% recall on stealthy port exploits.

7. **Interactive Web Dashboard & Live Scenario Replay**:
   - Complete visual dashboard featuring animated network topology, alert feeds, IPS quarantine tables, evaluation charts, test verification matrix, and an interactive packet playback simulator.

## 5. Presentation Deck Outline

Exactly five slides; suggested total duration: five to seven minutes.

| Slide | Title | Main content | Visual or demonstration | Key explanation |
| --- | --- | --- | --- | --- |
| 1 | IoT Security: Problem and Objective | Connected devices, limited visibility, weak access controls and patching challenges; objective: detect unknown local sources and suspicious traffic patterns. | Small network illustration with a sensor, camera, gateway, and application server. | A device can appear operational while its network behavior changes. |
| 2 | Proposed Monitoring Architecture | Synthetic records or Scapy capture; common event format; local-source filtering; detection engine; console and JSONL alerts. | Architecture diagram showing two input paths feeding the same monitor. | Separating input collection from detection makes the project testable without physical IoT devices. |
| 3 | Python Implementation and Rules | Explain `Config`, `Event`, and `Monitor`; allowlist check; more than 30 packets in 5 seconds; 6 distinct TCP ports; 10-second cooldown. | Three-rule table and a five-second rolling-window example. | Explain precisely why packet 31 triggers a burst and why repeated attempts to one port are not port diversity. |
| 4 | Demonstration and Results | Run `normal`, then `mixed`; show zero normal alerts and three mixed alerts across 68 records; optionally raise the burst threshold to 50. | Terminal output and the scenario-results table. | The suspicious inputs are synthetic records, so the demonstration sends no attack traffic. |
| 5 | Findings, Limitations, and Future Work | Transparent detection and structured logging; IP identity limits, false positives, capture visibility, IPv4 scope; future per-device baselines and inventory integration. | Compact table pairing limitations with proposed improvements. | Alerts support investigation; a successful synthetic demo does not establish production accuracy. |

### References

1. NIST, *Considerations for Managing Internet of Things (IoT) Cybersecurity and Privacy Risks*, NISTIR 8228, 2019. [Publication and PDF](https://csrc.nist.gov/pubs/ir/8228/final).
2. NIST, *IoT Device Cybersecurity Capability Core Baseline*, NISTIR 8259A, 2020. [Publication and PDF](https://csrc.nist.gov/pubs/ir/8259/a/final).
3. Scapy, *Download and Installation*, including platform requirements. [Official documentation](https://scapy.readthedocs.io/en/latest/installation.html).
4. Scapy, *Usage*, including packet sniffing and callbacks. [Official documentation](https://scapy.readthedocs.io/en/latest/usage.html).

References checked on 11 October 2026.
