# backend/simulator/log_simulator.py
"""
Replays events from a scenario at human-visible speed.
Sends POST requests to /ingest/logs with a configurable delay between batches.
"""
import time
import json
import requests
from typing import List, Dict
from simulator.attack_scenarios import ALL_SCENARIOS


BASE_URL = "http://127.0.0.1:8000"


def replay_scenario(
    scenario_name: str,
    delay_seconds: float = 2.0,
    batch_size: int = 1,
):
    """
    Replay a named attack scenario against the live API.
    delay_seconds: pause between event batches (for visual effect on dashboard).
    """
    events = ALL_SCENARIOS.get(scenario_name)
    if not events:
        print(f"[Simulator] Unknown scenario: {scenario_name}. "
              f"Choose from: {list(ALL_SCENARIOS.keys())}")
        return

    print(f"[Simulator] Starting scenario '{scenario_name}' ({len(events)} events)...")

    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        payload = {"logs": batch}
        try:
            resp = requests.post(
                f"{BASE_URL}/ingest/logs",
                json=payload,
                timeout=10,
            )
            resp.raise_for_status()
            result = resp.json()
            print(f"[Simulator] Sent event {i+1}/{len(events)} → "
                  f"graph: {result.get('graph_nodes', '?')} nodes, "
                  f"alerts: {result.get('alerts_triggered', 0)}")
        except Exception as e:
            print(f"[Simulator] Error sending event {i+1}: {e}")

        time.sleep(delay_seconds)

    print(f"[Simulator] Scenario '{scenario_name}' complete.")


if __name__ == "__main__":
    import sys
    scenario = sys.argv[1] if len(sys.argv) > 1 else "apt_phishing"
    replay_scenario(scenario, delay_seconds=2.0)
