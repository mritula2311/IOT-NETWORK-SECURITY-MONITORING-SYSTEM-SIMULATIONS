#!/usr/bin/env python3
"""Evaluator: compare baseline (single threshold) vs proposed (per-device) monitor."""

import json
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from iot_monitor import Config, Monitor, Event
from src.device_registry import DeviceRegistry
from src.monitor_enhanced import EnhancedMonitor
from src.scenario_loader import load_scenario


def run_baseline(events, config=None):
    """Run the original baseline monitor on a list of events."""
    if config is None:
        config = Config()
    alerts = []
    monitor = Monitor(config, alerts.append)
    for event in events:
        monitor.process(event)
    return {
        "alerts": alerts,
        "counts": dict(monitor.counts),
        "observed": monitor.observed,
        "monitored": monitor.monitored,
    }


def run_enhanced(events, registry, subnet="192.168.50.0/24"):
    """Run the enhanced per-device monitor on a list of events."""
    alerts = []
    monitor = EnhancedMonitor(
        registry=registry,
        subnet=subnet,
        emit=alerts.append
    )
    for event in events:
        monitor.process(event)
    return {
        "alerts": alerts,
        "counts": dict(monitor.counts),
        "observed": monitor.observed,
        "monitored": monitor.monitored,
        "summary": monitor.get_summary(),
    }


def compute_metrics(alerts, labels, alert_sources):
    """Compute precision, recall, and false-positive rate.

    An event source that appears in any alert is considered 'flagged'.
    Labels map event_ids to 'normal' or 'suspicious'.

    For episode-level evaluation:
    - TP: suspicious source got an alert
    - FP: normal-only source got an alert
    - FN: suspicious source got no alert
    - TN: normal-only source got no alert
    """
    # Group labels by source
    suspicious_sources = set()
    normal_sources = set()
    for eid, label in labels.items():
        # We need to figure out which source is associated with each event_id
        # For simplicity, use the alert_sources mapping
        pass

    # Simpler approach: count alerts that match suspicious vs normal labels
    # We consider an alert a TP if its source IP appears in any suspicious event
    tp = fp = fn = tn = 0

    # Get all unique sources from labels context
    source_labels = {}  # source_ip -> set of labels
    for eid, label in labels.items():
        # Parse source from event_id context
        pass

    # Use alert_sources directly
    flagged_sources = set(a.get("source", "") for a in alerts)

    for src, lbl in alert_sources.items():
        if src in flagged_sources:
            if lbl == "suspicious":
                tp += 1
            else:
                fp += 1
        else:
            if lbl == "suspicious":
                fn += 1
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
    recall = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) > 0 else float("nan")

    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": round(precision, 4) if precision == precision else "N/A",
        "recall": round(recall, 4) if recall == recall else "N/A",
        "false_positive_rate": round(fpr, 4) if fpr == fpr else "N/A",
    }


def evaluate_scenario(scenario_path, policy_path):
    """Run both monitors on a scenario and compare results."""
    events, labels = load_scenario(scenario_path)

    # Build source-level labels (a source is suspicious if any of its events is)
    source_labels = {}
    for event, (i, _) in zip(events, enumerate(events)):
        eid = f"AUTO_{i:04d}"
        # Find matching label
        for lid, lbl in labels.items():
            pass
    # Simpler: iterate records directly
    import json as _json
    with open(scenario_path) as f:
        records = _json.load(f)
    source_labels = {}
    for rec in records:
        src = rec["src"]
        lbl = rec.get("label", "normal")
        if lbl == "suspicious":
            source_labels[src] = "suspicious"
        elif src not in source_labels:
            source_labels[src] = "normal"

    # Run baseline
    baseline = run_baseline(events)

    # Run enhanced
    registry = DeviceRegistry(policy_path)
    enhanced = run_enhanced(events, registry)

    # Compute metrics
    baseline_metrics = compute_metrics(
        baseline["alerts"], labels, source_labels
    )
    enhanced_metrics = compute_metrics(
        enhanced["alerts"], labels, source_labels
    )

    return {
        "scenario": str(scenario_path),
        "total_events": len(events),
        "baseline": {
            "alert_count": len(baseline["alerts"]),
            "alert_rules": baseline["counts"],
            "metrics": baseline_metrics,
        },
        "enhanced": {
            "alert_count": len(enhanced["alerts"]),
            "alert_rules": enhanced["counts"],
            "metrics": enhanced_metrics,
        },
    }


def print_comparison(result):
    """Print a formatted comparison table."""
    print("\n" + "=" * 70)
    print(f"  EVALUATION: {Path(result['scenario']).stem}")
    print(f"  Total events: {result['total_events']}")
    print("=" * 70)

    for approach in ("baseline", "enhanced"):
        data = result[approach]
        m = data["metrics"]
        label = "BASELINE (single threshold=30)" if approach == "baseline" \
            else "PROPOSED (per-device thresholds)"
        print(f"\n  {label}")
        print(f"  {'─' * 40}")
        print(f"  Alerts fired:      {data['alert_count']}")
        print(f"  Alert breakdown:   {data['alert_rules']}")
        print(f"  TP={m['TP']}  FP={m['FP']}  FN={m['FN']}  TN={m['TN']}")
        print(f"  Precision:         {m['precision']}")
        print(f"  Recall:            {m['recall']}")
        print(f"  False-positive rate: {m['false_positive_rate']}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    scenarios_dir = Path(__file__).resolve().parent.parent / "scenarios"
    policy_path = Path(__file__).resolve().parent.parent / "config" / "device_policy.json"

    for scenario_file in sorted(scenarios_dir.glob("*.json")):
        result = evaluate_scenario(scenario_file, policy_path)
        print_comparison(result)
