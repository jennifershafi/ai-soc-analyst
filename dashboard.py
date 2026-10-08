import streamlit as st

from src.ingestion.parser import load_security_events
from src.ai.analyst import (
    collect_alerts,
    build_incident_context,
    analyze_with_local_ai,
)

st.set_page_config(
    page_title="AI SOC Analyst",
    layout="wide"
)

st.title("AI SOC Analyst")
st.caption("AI-assisted Security Operations Center investigation platform")

events = load_security_events("data/security_events.json")
alerts = collect_alerts(events)
incident = build_incident_context(alerts)

high_alerts = sum(
    1 for alert in alerts
    if alert.get("severity") == "high"
)

medium_alerts = sum(
    1 for alert in alerts
    if alert.get("severity") == "medium"
)

col1, col2, col3 = st.columns(3)

col1.metric("Total Alerts", len(alerts))
col2.metric("High Severity", high_alerts)
col3.metric("Medium Severity", medium_alerts)

st.divider()

st.subheader("Security Alerts")

for alert in alerts:
    severity = alert.get("severity", "unknown").upper()
    rule = alert.get("rule", "UNKNOWN")

    with st.expander(f"{severity} — {rule}"):
        st.write("**User:**", alert.get("username"))
        st.write("**Source IP:**", alert.get("source_ip"))
        st.write("**Description:**", alert.get("description"))

        if alert.get("resource"):
            st.write("**Resource:**", alert.get("resource"))

        if alert.get("timestamp"):
            st.write("**Timestamp:**", alert.get("timestamp"))
st.divider()
st.subheader("AI Investigation")

if st.button("Analyze Incident"):
    with st.spinner("Analyzing security evidence..."):
        analysis = analyze_with_local_ai(incident)

    st.markdown(analysis)
