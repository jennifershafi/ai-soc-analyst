from collections import defaultdict
from src.ingestion.parser import load_security_events


def detect_repeated_login_failures(events, threshold=5):
    failure_counts = defaultdict(int)
    alerts = []

    for event in events:
        if event.get("event_type") == "login_failed":
            key = (
                event.get("username"),
                event.get("source_ip")
            )
            failure_counts[key] += 1

    for (username, source_ip), count in failure_counts.items():
        if count >= threshold:
            alerts.append({
                "rule": "REPEATED_LOGIN_FAILURES",
                "severity": "medium",
                "username": username,
                "source_ip": source_ip,
                "failed_attempts": count,
                "description": (
                    f"{count} failed login attempts detected for "
                    f"{username} from {source_ip}"
                )
            })

    return alerts


def detect_suspicious_login_chain(events, threshold=5):
    failure_counts = defaultdict(int)
    alerts = []

    for event in events:
        username = event.get("username")
        source_ip = event.get("source_ip")
        event_type = event.get("event_type")

        key = (username, source_ip)

        if event_type == "login_failed":
            failure_counts[key] += 1

        elif event_type == "login_success":
            if failure_counts[key] >= threshold:
                alerts.append({
                    "rule": "FAILED_LOGINS_THEN_SUCCESS",
                    "severity": "high",
                    "username": username,
                    "source_ip": source_ip,
                    "failed_attempts": failure_counts[key],
                    "timestamp": event.get("timestamp"),
                    "description": (
                        f"{username} successfully authenticated from "
                        f"{source_ip} after {failure_counts[key]} failed attempts"
                    )
                })

    return alerts


def detect_post_login_file_activity(events, threshold=5):
    failure_counts = defaultdict(int)
    suspicious_sessions = set()
    alerts = []

    for event in events:
        username = event.get("username")
        source_ip = event.get("source_ip")
        event_type = event.get("event_type")

        key = (username, source_ip)

        if event_type == "login_failed":
            failure_counts[key] += 1

        elif event_type == "login_success":
            if failure_counts[key] >= threshold:
                suspicious_sessions.add(key)

        elif event_type in ("file_access", "file_download"):
            if key in suspicious_sessions:
                alerts.append({
                    "rule": "POST_LOGIN_FILE_ACTIVITY",
                    "severity": "high",
                    "username": username,
                    "source_ip": source_ip,
                    "activity": event_type,
                    "resource": event.get("resource"),
                    "timestamp": event.get("timestamp"),
                    "description": (
                        f"{username} performed {event_type} on "
                        f"{event.get('resource')} after suspicious authentication"
                    )
                })

    return alerts


if __name__ == "__main__":
    events = load_security_events("data/security_events.json")

    alerts = (
        detect_repeated_login_failures(events)
        + detect_suspicious_login_chain(events)
        + detect_post_login_file_activity(events)
    )

    print(f"\nGenerated {len(alerts)} alert(s)\n")

    for alert in alerts:
        print(f"Rule: {alert['rule']}")
        print(f"Severity: {alert['severity']}")
        print(f"User: {alert['username']}")
        print(f"Source IP: {alert['source_ip']}")

        if "failed_attempts" in alert:
            print(f"Failed attempts: {alert['failed_attempts']}")

        if "activity" in alert:
            print(f"Activity: {alert['activity']}")

        if "resource" in alert:
            print(f"Resource: {alert['resource']}")

        print(f"Description: {alert['description']}")
        print("-" * 50)
