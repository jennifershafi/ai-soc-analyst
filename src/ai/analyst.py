import json

from src.ingestion.parser import load_security_events
from src.detection.engine import (
    detect_repeated_login_failures,
    detect_suspicious_login_chain,
    detect_post_login_file_activity,
)


def collect_alerts(events):
    alerts = (
        detect_repeated_login_failures(events)
        + detect_suspicious_login_chain(events)
        + detect_post_login_file_activity(events)
    )

    return alerts


def build_incident_context(alerts):
    if not alerts:
        return {
            "status": "no_alerts",
            "alert_count": 0,
            "evidence": []
        }

    users = sorted({
        alert.get("username")
        for alert in alerts
        if alert.get("username")
    })

    source_ips = sorted({
        alert.get("source_ip")
        for alert in alerts
        if alert.get("source_ip")
    })

    return {
        "status": "requires_investigation",
        "alert_count": len(alerts),
        "affected_users": users,
        "source_ips": source_ips,
        "evidence": alerts
    }


if __name__ == "__main__":
    events = load_security_events("data/security_events.json")

    alerts = collect_alerts(events)
    incident = build_incident_context(alerts)

    print("\nAI SOC Analyst - Incident Context\n")
    print(json.dumps(incident, indent=4))
