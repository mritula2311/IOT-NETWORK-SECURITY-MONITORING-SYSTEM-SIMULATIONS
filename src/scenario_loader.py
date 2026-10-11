#!/usr/bin/env python3
"""Load scenario events from JSON files with ground-truth labels."""

import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from iot_monitor import Event


def load_scenario(scenario_path):
    """Load events from a JSON scenario file.

    Each record must have: elapsed_s, src, dst, protocol, dport, initial_syn.
    Optional fields: event_id, label (for evaluation).

    Returns:
        events: list of Event objects (sorted by elapsed_s)
        labels: dict mapping event_id -> label string
    """
    path = Path(scenario_path)
    if not path.exists():
        raise FileNotFoundError(f"Scenario file not found: {scenario_path}")

    with open(path, "r", encoding="utf-8") as f:
        records = json.load(f)

    if not isinstance(records, list):
        raise ValueError("Scenario file must contain a JSON array of event records.")

    events = []
    labels = {}

    for i, rec in enumerate(records):
        # Validate required fields
        required = ["elapsed_s", "src", "dst"]
        for field in required:
            if field not in rec:
                raise ValueError(
                    f"Record {i} missing required field '{field}': {rec}"
                )

        event = Event(
            t=float(rec["elapsed_s"]),
            src=rec["src"],
            dst=rec["dst"],
            protocol=rec.get("protocol", "TCP"),
            dport=int(rec.get("dport", 8883)),
            initial_syn=bool(rec.get("initial_syn", False))
        )
        events.append(event)

        # Store label for evaluation if present
        event_id = rec.get("event_id", f"AUTO_{i:04d}")
        if "label" in rec:
            labels[event_id] = rec["label"]

    # Sort by timestamp
    events.sort(key=lambda e: e.t)
    return events, labels


def list_scenarios(scenarios_dir):
    """List all .json scenario files in a directory."""
    path = Path(scenarios_dir)
    if not path.is_dir():
        return []
    return sorted(path.glob("*.json"))
