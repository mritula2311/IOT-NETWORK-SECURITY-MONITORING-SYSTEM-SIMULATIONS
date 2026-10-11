# IoT Network Security Monitoring System Using Python

## Title
**IoT Network Security Monitoring System with Device-Aware Behavioral Profiling and Automated Active Defense**

---

## Objective
The objective of this project is to design, implement, and evaluate a lightweight, transparent, and robust network security monitoring system tailored for Internet of Things (IoT) environments using Python. Specifically, the project aims to:
1. Passively inspect IPv4 packet metadata (source IP, destination IP, protocol, destination port, TCP flags, and timestamps) without invasive payload decryption.
2. Eliminate false positives caused by rigid, global thresholding by establishing **per-device behavioral baselines** (e.g., distinguishing high-bandwidth security cameras from low-power environmental sensors).
3. Enforce **Zero-Trust service and port whitelisting** to detect low-rate, stealthy IoT malware propagation (such as Mirai-style botnets scanning or connecting over Telnet/SSH).
4. Calculate composite, dynamic **Device Threat Scores (0–100)** with tiered risk classifications (`SECURE`, `ELEVATED`, `SUSPICIOUS`, `COMPROMISED`).
5. Execute **Automated Active Defense (IPS Mitigation)** by generating firewall isolation rules (`iptables -I FORWARD -s <IP> -j DROP`) to quarantine compromised nodes and drop subsequent traffic.
6. Provide an interactive, responsive **Web Dashboard** featuring real-time network topology visualization, alert feeds with explainable context, and interactive packet simulation playback.
7. Validate system correctness through a formal **14-case security test suite (TC01–TC14)** and benchmark empirical performance against traditional single-threshold monitors across multiple attack scenarios.

---

## Introduction
The Internet of Things (IoT) encompasses interconnected computing devices, mechanical machines, smart sensors, and controllers embedded within home automation, industrial facilities, and healthcare ecosystems. While these devices offer unprecedented automation and operational intelligence, they present major cybersecurity vulnerabilities:
* Many IoT nodes operate with constrained CPU, memory, and battery capacity, precluding heavy endpoint security agents or full antivirus software.
* Device fleets frequently run outdated firmware, lack cryptographically enforced access controls, and expose default administrative credentials.
* Once a single node is compromised, attackers readily establish lateral movement, turn devices into DDoS botnets (e.g., Mirai, Bashlite), or conduct internal reconnaissance.

According to NIST cybersecurity guidelines (NISTIR 8228 and NISTIR 8259A), network-level visibility and cybersecurity state awareness form critical baseline requirements. This project realizes these principles by creating a modular, lightweight Python-based monitoring engine capable of running on central IoT gateways, edge routers, or lightweight inspection nodes.

---

## Problem Statement
Conventional Network Intrusion Detection Systems (NIDS) and baseline threshold monitors face two fundamental architectural flaws when deployed in IoT subnets:

1. **The Fixed-Threshold Dilemma (High False-Positive Rate):**
   * Traditional monitors apply a single, static packet-rate threshold (e.g., 30 packets per 5-second window) across all subnet IPs.
   * Legitimate IoT devices possess vastly differing operational profiles: an RTSP IP camera streaming video bursts easily exceeds 30 packets, triggering continuous false alarms (`False Positives`). Conversely, a low-frequency temperature sensor normally transmitting 1 packet every 10 seconds can spike to 25 packets during an exfiltration attempt without ever reaching the threshold, completely evading detection (`False Negatives`).
2. **Blindness to Low-Rate Semantic Exploits:**
   * Attackers who recognize packet volume limits execute low-rate reconnaissance or open connections to unauthorized services (e.g., Telnet on port 23, SSH on port 22, or unauthorized MQTT brokers). Volume-only monitors completely miss these semantic violations.
3. **Passive-Only Logging Lacking Rapid Containment:**
   * Traditional monitoring solutions output logs for offline inspection without real-time quarantine, allowing automated botnet infections to propagate across local IoT subnets within seconds.

---

## Proposed System
To solve these challenges, this project introduces a **Device-Aware IoT Security Monitor with Active Defense**:

```
+-----------------------------------------------------------------------------------+
|                            IoT MONITOR ARCHITECTURE                               |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [ IoT Network Traffic / PCAP / Scenario Events ]                                 |
|                         │                                                         |
|                         ▼                                                         |
|             [ IPv4 Subnet Validation Filter ] ──► External IPs Ignored           |
|                         │                                                         |
|                         ▼                                                         |
|            [ Device Profile Registry ] (config/device_policy.json)               |
|            ├── Per-device Burst Thresholds (Sensor=10, Camera=40, etc.)           |
|            └── Zero-Trust Port Whitelist (TempSensor: [1883, 8883])               |
|                         │                                                         |
|                         ▼                                                         |
|            [ Multi-Rule Anomaly Detection Engine ]                                |
|            ├── Rule 1: UNKNOWN_IP (Rogue / Unregistered device)                  |
|            ├── Rule 2: UNAUTHORIZED_SERVICE (Port policy violation)               |
|            ├── Rule 3: TRAFFIC_BURST (Device-specific rate exceeded)              |
|            └── Rule 4: PORT_SCAN_PATTERN (>=6 distinct SYN destination ports)     |
|                         │                                                         |
|                         ▼                                                         |
|            [ Composite Threat Scoring & IPS Quarantine ]                          |
|            ├── Threat Score (0-100) Accumulator                                   |
|            ├── Severity Mapping (LOW, MEDIUM, HIGH, CRITICAL)                     |
|            └── Active IPS: Auto-generates 'iptables -s <ip> -j DROP' & drops pkts |
|                         │                                                         |
|        ┌────────────────┴────────────────┬────────────────────────┐               |
|        ▼                                 ▼                        ▼               |
|  [ Explainable Logs ]           [ Web Dashboard ]        [ Security Test Suite ]  |
|  (JSON / JSON Lines)        (Topology, Playback, IPS)         (TC01 - TC14)       |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### Key Innovations of the Proposed System:
1. **Device Registry Integration:** Loads role-specific configurations (`sensor`, `camera`, `gateway`, `server`) from a clean JSON policy specification.
2. **Multi-Vector Threat Detection:**
   * **Rule 1 (`UNKNOWN_IP`):** Flags unregistered local IP addresses.
   * **Rule 2 (`UNAUTHORIZED_SERVICE`):** Enforces Zero-Trust port profiles per device.
   * **Rule 3 (`TRAFFIC_BURST`):** Evaluates a sliding rolling window against individual device thresholds.
   * **Rule 4 (`PORT_SCAN_PATTERN`):** Tracks initial TCP SYN packets (`SYN=1, ACK=0`) across distinct destination ports per destination pair.
3. **Sliding Time Window & Cooldown Engine:** Uses deque-based rolling windows (`cutoff = t - window`) and a 10-second suppression cooldown to prevent alert flooding while ensuring independent rule firing.
4. **Active Defense (IPS Isolation):** Upon reaching a threat score threshold (>=60) or on critical triggers, the device status transitions to `QUARANTINED`, emitting simulated firewall drop commands and dropping subsequent packets from the infected source.
5. **Full Transparency & Explainability:** Every alert emitted contains the timestamp, rule name, severity tier, source/destination IP, destination port, device role, the exact threshold evaluated, and an explanation of the anomaly.

---

## System Architecture

### 1. Architectural Components
* **`DeviceRegistry` (`src/device_registry.py`):** Loads and parses device profiles from `config/device_policy.json`. Provides `O(1)` IP registration validation, dynamic burst threshold retrieval, and port authorization verification.
* **`EnhancedMonitor` (`src/monitor_enhanced.py`):** The primary detection and mitigation engine. Manages state queues, sliding time windows, port scan frequency tables, cooldown timers, threat score accumulation, and packet drop enforcement.
* **`ScenarioLoader` (`src/scenario_loader.py`):** Ingestion adapter converting JSON attack/normal episode recordings into standardized `Event` instances with time order and integrity verification.
* **`Evaluator` (`src/evaluator.py`):** Comparative analytics engine calculating True Positives (TP), False Positives (FP), False Negatives (FN), True Negatives (TN), Precision, Recall, and False-Positive Rate across benchmark scenarios.
* **`TestRunner` (`src/test_runner.py`):** Automated harness executing test cases TC01 through TC14 and saving structured results to `evidence/test_results.json`.
* **`Web Dashboard` (`dashboard/`):** Pure HTML5/CSS3/Vanilla JavaScript single-page application with animated topology graph, filterable alert feed, live scenario playback controls, and active IPS quarantine matrix.

### 2. Monitored Network Topology Model
Monitored Subnet: **`192.168.50.0/24`**

| Device Name | IP Address | Role | Configured Burst Threshold | Authorized Service Ports | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Gateway-01** | `192.168.50.1` | Gateway | 50 pkts / 5.0s | 53, 80, 443, 8883, 8000, 8080 | Default router & upstream DNS/HTTP proxy |
| **TempSensor-01** | `192.168.50.10` | Sensor | 10 pkts / 5.0s | 1883, 8883 | Environmental sensor (MQTT / MQTTS telemetry) |
| **Camera-01** | `192.168.50.11` | Camera | 40 pkts / 5.0s | 80, 443, 554, 8883, 8080 | RTSP video stream & HTTP management |
| **AppServer-01** | `192.168.50.20` | Server | 60 pkts / 5.0s | 80, 443, 1883, 8883, 8000, 8080 | Central IoT broker, database, and backend |
| *Rogue Attacker* | `192.168.50.99` | Unknown | 30 pkts / 5.0s (default) | None (Unregistered) | Simulated rogue IoT node / compromised device |

---

## Tools and Technologies Used
* **Programming Language:** Python 3.10+ (Tested & verified on Python 3.12).
* **Standard Python Libraries:**
  * `ipaddress`: Strict subnet validation and CIDR parsing.
  * `collections.deque`, `Counter`: High-efficiency rolling window state queues and statistical summaries.
  * `dataclasses`: Type-hinted, immutable internal records (`Event`, `DeviceProfile`).
  * `json`: Parsing policies, reading scenarios, and serializing evidence.
  * `math`, `time`, `datetime`, `uuid`: Timestamp arithmetic, ISO formatting, and run tracking.
  * `pathlib`: Cross-platform OS path abstraction.
* **Frontend Dashboard:**
  * HTML5 (Semantic document hierarchy and accessibility).
  * Vanilla CSS3 (Custom design system, glassmorphism, responsive grid, and micro-animations; no third-party framework dependencies).
  * Vanilla JavaScript ES6+ (Async data fetching, SVG network nodes, dynamic DOM updates, and interval-based playback simulation).
* **Optional Network Capture Integration:**
  * Scapy (supported via `iot_monitor.py --mode live` when Npcap/libpcap drivers are installed).
* **Version Control:** Git & GitHub.

---

## Methodology / Working

```
 Packet Received (Event: t, src, dst, proto, dport, flags)
                           │
                           ▼
          Is source IP in monitored subnet (192.168.50.0/24)?
             ├── NO  ──► Discard (External source out of scope)
             └── YES ──► Continue
                           │
                           ▼
           Is source IP currently in QUARANTINED state?
             ├── YES ──► Increment blocked_packets counter & DROP packet
             └── NO  ──► Continue
                           │
                           ▼
          Expire timestamps in rolling window older than (t - 5.0s)
                           │
                           ▼
          [Rule 1] Is src in registered allowlist?
             ├── NO  ──► Emit UNKNOWN_IP alert (Severity: HIGH, Score: +35)
             └── YES ──► Continue
                           │
                           ▼
          [Rule 2] Is dport permitted in device's service profile?
             ├── NO  ──► Emit UNAUTHORIZED_SERVICE alert (Severity: HIGH, Score: +35)
             └── YES ──► Continue
                           │
                           ▼
          [Rule 3] Do packet count in 5s exceed device-specific threshold?
             ├── YES ──► Emit TRAFFIC_BURST alert (Severity: MEDIUM, Score: +25)
             └── NO  ──► Continue
                           │
                           ▼
          [Rule 4] Is protocol TCP with initial SYN (SYN=1, ACK=0)?
             ├── YES ──► Track distinct dport per destination.
             │           If distinct ports in window >= 6:
             │           Emit PORT_SCAN_PATTERN alert (Severity: CRITICAL, Score: +50)
             └── NO  ──► Continue
                           │
                           ▼
          Threat Assessment:
             If updated Threat Score >= 60 OR Severity == 'CRITICAL':
             - Mark device as QUARANTINED
             - Issue mitigation rule: iptables -I FORWARD -s <src> -j DROP
             - Log active defense action
```

---

## Implementation Details

### Project Directory Structure
```
iot_security_monitor/
├── IoT_Network_Security_Monitor_Guide.md     # Comprehensive academic documentation
├── IoT_Security_Mini_Project_Roadmap.md      # Implementation roadmap and milestones
├── README.md                                 # Complete project specification and guide
├── iot_monitor.py                            # Baseline monitor implementation & CLI
├── run_project.py                            # One-click execution script for entire pipeline
├── test_monitor.py                           # Baseline unit tests
├── requirements-optional.txt                 # Optional dependencies (Scapy)
├── config/
│   └── device_policy.json                   # Network subnet, device thresholds & port policies
├── src/
│   ├── __init__.py                          # Package initializer
│   ├── device_registry.py                   # Device profiles & threshold lookup engine
│   ├── monitor_enhanced.py                  # Enhanced multi-rule monitor & IPS quarantine
│   ├── scenario_loader.py                   # JSON scenario loader & event parser
│   ├── evaluator.py                         # Evaluation framework (Precision, Recall, FPR)
│   └── test_runner.py                       # Automated test suite runner (TC01 - TC14)
├── scenarios/
│   ├── normal.json                          # Normal telemetry baseline
│   ├── camera_burst.json                    # Legitimate high-throughput camera traffic
│   ├── mixed_attack.json                    # Multi-stage attack (Unknown IP + Burst + Scan)
│   └── unauthorized_service.json            # Stealthy malware unauthorized port exploit
├── dashboard/
│   ├── index.html                           # Single-page web dashboard
│   ├── style.css                            # Glassmorphic dark styling & animations
│   ├── app.js                               # Dashboard rendering & traffic simulator
│   └── data.json                            # Serialized execution evidence and telemetry
└── evidence/
    ├── test_results.json                    # Formal test execution evidence
    └── dashboard_data.json                  # Archived evaluation and telemetry data
```

### Key Python Module Implementations

1. **Device Registry (`src/device_registry.py`):**
   * Encapsulates `DeviceProfile` as an immutable frozen dataclass.
   * Validates IP syntax via `ipaddress.IPv4Address`.
   * Enforces role-based thresholds and `allowed_ports` sets.

2. **Detection & IPS Engine (`src/monitor_enhanced.py`):**
   * Uses `collections.deque` with `maxlen = device_threshold + 1` for memory-bounded sliding windows.
   * Tracks TCP connection attempts using `(source, dest) -> {port: timestamp}` dictionaries.
   * Implements a 10-second rule cooldown preventing alert storming while allowing independent rules to trigger.
   * Evaluates composite risk scores and triggers automated quarantine with packet dropping.

3. **Scenario Testing & Evaluation (`src/evaluator.py`):**
   * Calculates Episode-level metrics:
     $$\text{Precision} = \frac{TP}{TP + FP}$$
     $$\text{Recall} = \frac{TP}{TP + FN}$$
     $$\text{False Positive Rate (FPR)} = \frac{FP}{FP + TN}$$

---

## Test Cases

The project incorporates 14 formal, automated test cases executed via `src/test_runner.py`. Every test is executed on clean instances to ensure deterministic results.

| Test ID | Test Case Name | Tested Condition | Expected Result | Actual Result | Status |
| :---: | :--- | :--- | :--- | :--- | :---: |
| **TC01** | Normal Sensor Traffic | 8 periodic telemetry packets from registered sensors | 0 alerts fired | 0 alerts fired | **PASS** |
| **TC02** | Unknown Source Detection | Packet originates from unregistered IP `192.168.50.99` | `UNKNOWN_IP` alert generated | Alert fired: `True` | **PASS** |
| **TC03** | Device Burst Detection | 11 packets in 1s from TempSensor (Threshold = 10) | `TRAFFIC_BURST` alert generated | Alert fired: `True` (11 pkts, T=10) | **PASS** |
| **TC04** | Threshold Boundary Limit | Exactly 10 packets from TempSensor (Threshold = 10) | 0 burst alerts (strictly greater required) | Burst alerts: 0 | **PASS** |
| **TC05** | Window Expiry Verification | Events at $t=0, 1, 5$; window = 5.0s | Left boundary excluded; only $t=1, 5$ retained | Events in window: 2 | **PASS** |
| **TC06** | Distinct TCP Port Scan | 6 initial SYN packets to 6 distinct destination ports | `PORT_SCAN_PATTERN` alert generated | Alert fired: `True` (6 distinct ports) | **PASS** |
| **TC07** | Repeated Port Scan Invariance | 6 initial SYN packets to the same destination port (443) | 0 scan alerts (port diversity required) | Scan alerts: 0 | **PASS** |
| **TC08** | Malformed Data Rejection | Event timestamp is `NaN` or negative | `ValueError` raised and packet rejected | `ValueError` raised: `True` | **PASS** |
| **TC09** | Legitimate Camera Burst | 35 packets from Camera-01 (Baseline T=30, Camera T=40) | Baseline flags false alarm; Proposed accepts traffic | Baseline alerts: 1; Proposed alerts: 0 | **PASS** |
| **TC10** | Low-Rate Suspicious Traffic | Unknown IP transmits at low rate (below burst limit) | `UNKNOWN_IP` caught; Burst missed | `UNKNOWN_IP` caught; Burst not triggered | **PASS** |
| **TC11** | Cooldown & Re-Alerting | Trigger at $t=0$, event at $t=1$, event at $t=10$ | Alert at $t=0$, suppressed at $t=1$, re-alert at $t=10$ | Alerts generated: 2 ($t=0, 10$) | **PASS** |
| **TC12** | Log Privacy Inspection | Alert logs examined for prohibited identifiers | No passwords, payloads, or session tokens in logs | Prohibited fields found: none | **PASS** |
| **TC13** | Unauthorized Service Violation | TempSensor connects to unauthorized port 23 (Telnet) | `UNAUTHORIZED_SERVICE` alert generated | Alert fired: `True` (port 23 blocked) | **PASS** |
| **TC14** | Automated IPS Quarantine | Compromised node generates high-threat scan pattern | Device quarantined, firewall rule created, subsequent traffic dropped | Quarantined: `True`, Dropped pkts: 1 | **PASS** |

**Summary: 14 / 14 Tests Passed (100% Pass Rate).**

---

## Results and Discussion

### 1. Comparative Performance: Baseline vs. Proposed Monitor

Empirical evaluation was conducted across four comprehensive test scenarios:

#### Scenario A: `camera_burst.json` (35 Events — High-Throughput Video Streaming)
* **Baseline Monitor (Single Threshold = 30):**
  * Alerts: 1 (`TRAFFIC_BURST` false positive on Camera-01).
  * $TP = 0, FP = 1, FN = 0, TN = 0$
  * **Precision:** `0.0%` | **False-Positive Rate:** `100.0%`
* **Proposed Monitor (Device-Aware Threshold = 40):**
  * Alerts: 0 (Correctly recognized as nominal camera video burst).
  * $TP = 0, FP = 0, FN = 0, TN = 1$
  * **False-Positive Rate:** `0.0%` (False alarm completely eliminated).

#### Scenario B: `unauthorized_service.json` (6 Events — Stealthy Botnet Propagation)
* **Baseline Monitor (Single Threshold = 30):**
  * Alerts: 0 (Attacker sent only 3 Telnet connection attempts, slipping under the volume threshold).
  * $TP = 0, FP = 0, FN = 1, TN = 0$
  * **Recall:** `0.0%` (Attack went completely undetected).
* **Proposed Monitor (Zero-Trust Service Profile):**
  * Alerts: 1 (`UNAUTHORIZED_SERVICE` on port 23).
  * $TP = 1, FP = 0, FN = 0, TN = 0$
  * **Precision:** `100.0%` | **Recall:** `100.0%`
  * **Mitigation:** Node immediately quarantined with `iptables` drop rule.

#### Scenario C: `mixed_attack.json` (60 Events — Multi-Vector Intrusion)
* **Baseline Monitor:** Triggered 3 alerts (`UNKNOWN_IP`, `TRAFFIC_BURST`, `PORT_SCAN_PATTERN`).
* **Proposed Monitor:** Triggered 4 explainable alerts (identifying the specific unauthorized port probe in addition to volume and scan anomalies).

#### Scenario D: `normal.json` (8 Events — Nominal Telemetry)
* Both monitors produced 0 alerts, verifying baseline stability during regular traffic.

---

## Security Analysis

### Threat Model & Attack Surface Coverage
1. **Rogue Device Insertion:**
   * *Attack:* An adversary connects an unauthorized laptop or rogue micro-controller into the IoT subnet.
   * *Defense:* Caught immediately upon first packet transmission by Rule 1 (`UNKNOWN_IP`).
2. **Volumetric Denial of Service (DoS):**
   * *Attack:* Compromised smart sensor flooded with traffic to exhaust gateway buffers.
   * *Defense:* Detected by Rule 3 (`TRAFFIC_BURST`) when packet count exceeds device-specific threshold in any 5-second window.
3. **Reconnaissance & Lateral Port Scanning:**
   * *Attack:* Infected camera scans internal servers for open administrative services.
   * *Defense:* Caught by Rule 4 (`PORT_SCAN_PATTERN`) when SYN packets contact 6 or more distinct destination ports.
4. **Stealthy Botnet Exploitation (Mirai-style Telnet/SSH Scans):**
   * *Attack:* Malware conducts slow, low-frequency connections to default IoT ports (22, 23).
   * *Defense:* Caught by Rule 2 (`UNAUTHORIZED_SERVICE`) due to zero-trust port whitelisting, regardless of packet volume.
5. **Mitigation Bypass Resistance:**
   * *Attack:* Compromised node continues transmitting packets after detection.
   * *Defense:* The active IPS module drops subsequent packets at the monitor's input filter, simulating hardware firewall isolation.

### Privacy and Operational Safety
* **Zero Payload Inspection:** The system operates purely on Layer 3/Layer 4 packet headers, strictly preserving user data privacy (no credential interception, cookies, or payload content inspected or stored).
* **Deterministic Resource Consumption:** All sliding queues have fixed upper bounds, eliminating unbounded memory leaks during prolonged traffic bursts.

---

## Conclusion
This mini-project demonstrates that effective IoT network security monitoring does not require complex deep-packet inspection or resource-heavy machine learning models. By combining **per-device behavioral baselines**, **Zero-Trust port whitelisting**, and **automated IPS quarantine** in a lightweight, pure-Python architecture:
* False alarms from legitimate high-traffic devices (such as security cameras) are reduced to **0%**.
* Low-rate semantic attacks that bypass standard volume thresholds are detected with **100% recall**.
* Immediate automated containment is achieved through dynamic firewall drop rules.
* All 14 security test cases pass with 100% reliability, providing an accessible, transparent, and academically rigorous reference implementation for IoT network defense.

---

## Quick Start & Reproduction Commands

### 1. Run Complete Pipeline (One-Click)
```bash
python run_project.py
```

### 2. Run Formal Security Test Suite (TC01–TC14)
```bash
python src/test_runner.py
```

### 3. Run Comparative Evaluation Framework
```bash
python src/evaluator.py
```

### 4. Launch Interactive Web Dashboard
```bash
python -m http.server 8000 --directory dashboard
```
Open **`http://localhost:8000`** in any web browser to explore the real-time topology, alert feeds, IPS quarantine matrix, and interactive traffic simulator.
