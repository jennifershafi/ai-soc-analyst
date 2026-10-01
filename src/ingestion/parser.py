import json
from pathlib import Path


def load_security_events(file_path):
    """Load security events from a JSON file."""

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Security event file not found: {file_path}")

    with path.open("r", encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("Security event data must contain a list of events.")

    return events


if __name__ == "__main__":
    events = load_security_events("data/security_events.json")

    print(f"Loaded {len(events)} security events")

    for event in events:
        print(
            event.get("timestamp"),
            event.get("event_type"),
            event.get("username"),
            event.get("source_ip")
        )
