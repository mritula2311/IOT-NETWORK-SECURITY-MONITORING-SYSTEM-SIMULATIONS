"""Offline behavioral checks; no test sends packets or opens a capture socket."""

import importlib.util
import unittest
from dataclasses import replace

from iot_monitor import Config, Event, Monitor, packet_to_event, simulate


class MonitorTests(unittest.TestCase):
    def make_monitor(self, **changes):
        alerts = []
        return Monitor(replace(Config(), **changes), alerts.append), alerts

    def test_all_demonstration_scenarios(self):
        cases = {
            "normal": (20, {}),
            "unknown": (2, {"UNKNOWN_IP": 1}),
            "burst": (40, {"TRAFFIC_BURST": 1}),
            "scan": (6, {"PORT_SCAN_PATTERN": 1}),
            "mixed": (68, {"UNKNOWN_IP": 1, "TRAFFIC_BURST": 1,
                            "PORT_SCAN_PATTERN": 1}),
        }
        for scenario, (events, counts) in cases.items():
            with self.subTest(scenario=scenario):
                monitor, alerts = self.make_monitor()
                for event in simulate(scenario):
                    monitor.process(event)
                self.assertEqual(monitor.monitored, events)
                self.assertEqual(dict(monitor.counts), counts)
                self.assertEqual(len(alerts), sum(counts.values()))

    def test_rate_threshold_is_strictly_greater(self):
        monitor, alerts = self.make_monitor(threshold=3)
        for t in (0, 1, 2):
            monitor.process(Event(t, "192.168.50.10", "192.168.50.20"))
        self.assertEqual(alerts, [])
        monitor.process(Event(3, "192.168.50.10", "192.168.50.20"))
        self.assertEqual([a["rule"] for a in alerts], ["TRAFFIC_BURST"])

    def test_window_excludes_exact_left_boundary(self):
        monitor, alerts = self.make_monitor(threshold=2)
        for t in (0, 1, 5):
            monitor.process(Event(t, "192.168.50.10", "192.168.50.20"))
        self.assertEqual(alerts, [])
        self.assertEqual(list(monitor.recent["192.168.50.10"]), [1, 5])

    def test_repeated_port_and_non_syn_do_not_trigger_scan(self):
        monitor, alerts = self.make_monitor(threshold=100)
        for i in range(10):
            monitor.process(Event(i / 10, "192.168.50.11", "192.168.50.20",
                                  dport=443, initial_syn=True))
        for i in range(10):
            monitor.process(Event(1 + i / 10, "192.168.50.11", "192.168.50.20",
                                  dport=2000 + i, initial_syn=False))
        self.assertEqual(alerts, [])

    def test_scan_counts_expire_and_are_separate_per_destination(self):
        monitor, alerts = self.make_monitor(port_threshold=3)
        for t, dst, port in [(0, "192.168.50.20", 1),
                             (1, "192.168.50.20", 2),
                             (2, "192.168.50.1", 3),
                             (5, "192.168.50.20", 4)]:
            monitor.process(Event(t, "192.168.50.11", dst,
                                  dport=port, initial_syn=True))
        self.assertEqual(alerts, [])

    def test_cooldown_and_independent_rules(self):
        monitor, alerts = self.make_monitor(threshold=1)
        for t in (0, 1, 10):
            monitor.process(Event(t, "192.168.50.99", "192.168.50.20"))
        self.assertEqual([a["rule"] for a in alerts],
                         ["UNKNOWN_IP", "TRAFFIC_BURST", "UNKNOWN_IP"])

    def test_external_source_is_outside_scope(self):
        monitor, alerts = self.make_monitor()
        monitor.process(Event(0, "203.0.113.1", "192.168.50.10"))
        self.assertEqual((monitor.observed, monitor.monitored), (1, 0))
        self.assertEqual(alerts, [])

    def test_history_is_bounded_and_idle_state_expires(self):
        monitor, _ = self.make_monitor(threshold=3)
        for i in range(100):
            monitor.process(Event(i / 100, "192.168.50.10", "192.168.50.20"))
        self.assertEqual(len(monitor.recent["192.168.50.10"]), 4)
        monitor.process(Event(20, "192.168.50.11", "192.168.50.20"))
        self.assertNotIn("192.168.50.10", monitor.recent)
        self.assertEqual(monitor.last_alert, {})

    def test_configuration_and_timestamp_validation(self):
        for changes in ({"threshold": 0}, {"window": float("nan")},
                        {"cooldown": 0}, {"allowed": ("203.0.113.1",)},
                        {"subnet": "192.168.50.7/24"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.make_monitor(**changes)
        monitor, _ = self.make_monitor()
        monitor.process(Event(1, "192.168.50.10", "192.168.50.20"))
        with self.assertRaises(ValueError):
            monitor.process(Event(0, "192.168.50.10", "192.168.50.20"))

    @unittest.skipUnless(importlib.util.find_spec("scapy"), "Scapy is optional")
    def test_scapy_metadata_adapter_without_network_io(self):
        try:
            from scapy.all import ARP, Dot1Q, Ether, IP, IPv6, TCP, UDP
        except PermissionError as exc:
            self.skipTest(f"Environment blocks Scapy interface discovery: {exc}")

        base = Ether() / IP(src="192.168.50.10", dst="192.168.50.20")
        syn = packet_to_event(base / TCP(dport=443, flags="S"), 1)
        self.assertTrue(syn.initial_syn)
        self.assertEqual((syn.protocol, syn.dport), ("TCP", 443))
        syn_ack = packet_to_event(base / TCP(flags="SA"), 2)
        self.assertFalse(syn_ack.initial_syn)
        udp = packet_to_event(base / UDP(dport=123), 3)
        self.assertEqual((udp.protocol, udp.dport), ("UDP", 123))
        vlan = Ether() / Dot1Q() / IP(src="192.168.50.10") / TCP(flags="S")
        self.assertTrue(packet_to_event(vlan, 4).initial_syn)
        self.assertIsNone(packet_to_event(Ether() / ARP(), 5))
        self.assertIsNone(packet_to_event(Ether() / IPv6() / TCP(), 6))
        self.assertIsNone(packet_to_event(Ether() / IPv6() / IP() / TCP(), 7))
        fragmented = Ether() / IP(frag=1) / TCP(flags="S")
        self.assertFalse(packet_to_event(fragmented, 8).initial_syn)


if __name__ == "__main__":
    unittest.main(verbosity=2)
