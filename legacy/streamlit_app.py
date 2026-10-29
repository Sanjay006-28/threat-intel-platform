"""
app.py
Streamlit UI for the Threat Intelligence & IOC Correlation Platform.

Tabs:
  1. 🔍 Log Scanner & Correlation
  2. 🚨 Security Alerts
  3. 📚 Threat Intelligence DB
  4. 📊 Analytics Dashboard
"""

import json
import streamlit as st
import pandas as pd
from datetime import datetime

from database import (
    init_db, run_migrations,
    get_all_iocs, get_all_alerts,
    get_ioc_count, get_alert_count,
    get_ioc_type_distribution,
    get_alert_severity_distribution,
    get_alerts_daily_trend,
    get_top_malware_families,
)
from feed_collector import run_all_collectors
from correlator import CorrelationEngine
from generate_mock_logs import generate_sample_log_file
from scheduler import start_scheduler, get_last_sync_info

# ── Bootstrap ─────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Threat Intel & IOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()
run_migrations()
start_scheduler()          # auto-sync every 6 h (daemon thread)


# ── Cached resources ──────────────────────────────────────────────────────────
@st.cache_resource
def get_engine() -> CorrelationEngine:
    return CorrelationEngine()

engine = get_engine()


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ Threat Intel Platform")
    st.caption("Real-time IOC ingestion & log correlation engine")
    st.divider()

    # Live KPI badges
    col_a, col_b = st.columns(2)
    col_a.metric("IOCs in DB",   get_ioc_count())
    col_b.metric("Total Alerts", get_alert_count())

    st.divider()

    if st.button("🔄 Sync Threat Feeds Now", use_container_width=True):
        with st.spinner("Fetching IOCs from ThreatFox, URLhaus, MalwareBazaar, Feodo …"):
            res = run_all_collectors()
            engine.reload_cache()
        total_new = sum(res.values())
        st.success(f"✅ Sync complete! **{total_new}** new IOCs added")
        with st.expander("Feed breakdown"):
            for feed, count in res.items():
                st.write(f"• **{feed}**: {count} new")
        st.rerun()

    if st.button("📝 Create Demo Log File", use_container_width=True):
        generate_sample_log_file()
        st.success("Created `demo_security.log` — load it in the scanner tab!")

    st.divider()

    # Auto-sync status
    sync_info = get_last_sync_info()
    st.caption(f"⏱️ Last auto-sync: **{sync_info['time']}**")
    if sync_info["counts"]:
        total = sum(sync_info["counts"].values())
        st.caption(f"Added {total} new IOCs")
    st.caption("🔁 Auto-sync runs every **6 hours**")


# ── Main Tabs ─────────────────────────────────────────────────────────────────
tab_scan, tab_alerts, tab_iocs, tab_analytics = st.tabs([
    "🔍 Log Scanner & Correlation",
    "🚨 Security Alerts",
    "📚 Threat Intel DB",
    "📊 Analytics",
])

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1 — Log Scanner
# ═══════════════════════════════════════════════════════════════════════════════
with tab_scan:
    st.subheader("Ingest Security Logs & Detect Threats")
    col_left, col_right = st.columns([2, 1])

    with col_left:
        uploaded_file = st.file_uploader(
            "Upload Security Log File (.log, .txt, .csv)",
            type=["log", "txt", "csv"],
        )
        manual_logs = st.text_area(
            "Or paste raw log lines here:",
            height=180,
            placeholder="Paste log lines containing IPs, URLs, domains, emails, or hashes…",
        )

        if st.button("🚀 Run Correlation Engine", type="primary", use_container_width=True):
            log_content  = ""
            source_name  = "Manual Input"

            if uploaded_file is not None:
                log_content = uploaded_file.read().decode("utf-8", errors="ignore")
                source_name = uploaded_file.name
            elif manual_logs.strip():
                log_content = manual_logs

            if not log_content:
                st.warning("⚠️ Please upload a file or paste log text first.")
            else:
                with st.spinner("Running correlation engine…"):
                    alerts = engine.correlate_log_text(log_content, log_source=source_name)

                if alerts:
                    st.error(f"⚠️ **{len(alerts)} malicious IOC(s)** detected in `{source_name}`!")

                    # Severity colour map
                    sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}

                    for a in alerts:
                        icon = sev_icon.get(a["severity"].lower(), "⚪")
                        with st.expander(
                            f"{icon} [{a['severity'].upper()}]  {a['matched_ioc']}  —  {a['malware_family']}"
                        ):
                            c1, c2, c3 = st.columns(3)
                            c1.metric("IOC Type",        a["ioc_type"].upper())
                            c2.metric("Confidence",      f"{a['confidence_score']}%")
                            c3.metric("Threat Type",     a["threat_type"])

                            if a.get("attack_technique"):
                                st.info(
                                    f"🎯 **MITRE ATT&CK:** `{a['attack_technique']}` — "
                                    f"{a['attack_name']}"
                                )
                            st.code(a["raw_log_line"], language="text")
                else:
                    st.success(f"✅ Clean! No known IOCs matched in `{source_name}`.")

    with col_right:
        st.info("💡 **How it works**")
        st.markdown("""
**Step 1 — Extract entities**
Regex pulls out IPs, URLs, domains, emails, MD5, SHA1, SHA256 hashes.

**Step 2 — Correlate**
Each entity is checked against **{n}** cached threat indicators using:
- Exact match
- URL host extraction
- Fuzzy subdomain match

**Step 3 — Alert**
Matches generate alerts enriched with malware family, severity, and MITRE ATT&CK technique.
        """.format(n=engine.cache_size))

        st.info("📋 **Supported IOC Types**")
        st.markdown("""
| Type | Example |
|------|---------|
| IPv4 | `185.220.101.5` |
| Domain | `evil.top` |
| URL | `http://bad.xyz/x.exe` |
| Email | `spam@evil.top` |
| MD5 | `44d88612...` |
| SHA1 | `aabbccdd...` |
| SHA256 | `275a021b...` |
        """)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2 — Security Alerts
# ═══════════════════════════════════════════════════════════════════════════════
with tab_alerts:
    st.subheader("Correlated Threat Incidents")

    # Filters
    col_f1, col_f2, col_f3 = st.columns([1, 1, 2])
    sev_filter = col_f1.selectbox("Filter by severity", ["All", "critical", "high", "medium", "low"])
    limit_val  = col_f2.selectbox("Show last N alerts", [50, 100, 250, 500], index=1)

    alerts_data = get_all_alerts(
        limit=limit_val,
        severity=None if sev_filter == "All" else sev_filter
    )

    if alerts_data:
        df_alerts = pd.DataFrame(alerts_data)

        # Rename for display
        display_cols = {
            "timestamp":        "Time",
            "severity":         "Severity",
            "matched_ioc":      "Matched IOC",
            "ioc_type":         "Type",
            "malware_family":   "Malware Family",
            "attack_technique": "ATT&CK ID",
            "attack_name":      "ATT&CK Technique",
            "log_source":       "Log Source",
            "raw_log_line":     "Raw Log",
        }
        show_cols = [c for c in display_cols if c in df_alerts.columns]
        df_display = df_alerts[show_cols].rename(columns=display_cols)

        st.dataframe(df_display, use_container_width=True, height=420)

        # Export buttons
        st.divider()
        col_e1, col_e2 = st.columns(2)
        csv_bytes = df_display.to_csv(index=False).encode()
        col_e1.download_button(
            "⬇️ Export as CSV",
            data=csv_bytes,
            file_name=f"alerts_{datetime.now():%Y%m%d_%H%M}.csv",
            mime="text/csv",
        )
        json_bytes = df_alerts.to_json(orient="records", indent=2).encode()
        col_e2.download_button(
            "⬇️ Export as JSON",
            data=json_bytes,
            file_name=f"alerts_{datetime.now():%Y%m%d_%H%M}.json",
            mime="application/json",
        )
    else:
        st.info("No incidents detected yet. Run the Log Scanner from the first tab.")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3 — IOC Database
# ═══════════════════════════════════════════════════════════════════════════════
with tab_iocs:
    st.subheader("Normalized Threat Intelligence Indicators")

    col_t1, col_t2, col_t3 = st.columns([1, 1, 2])
    type_filter  = col_t1.selectbox("Filter by type", ["All", "ip", "domain", "url", "email", "md5", "sha1", "sha256"])
    ioc_limit    = col_t2.selectbox("Show N IOCs", [100, 250, 500, 1000], index=1)
    search_query = col_t3.text_input("🔎 Search IOC value / malware family", "")

    iocs_data = get_all_iocs(
        limit=ioc_limit,
        ioc_type=None if type_filter == "All" else type_filter
    )

    if iocs_data:
        df_iocs = pd.DataFrame(iocs_data)

        # Apply search filter
        if search_query.strip():
            mask = (
                df_iocs["ioc_value"].str.contains(search_query, case=False, na=False) |
                df_iocs["malware_family"].str.contains(search_query, case=False, na=False)
            )
            df_iocs = df_iocs[mask]

        display_ioc_cols = ["ioc_value", "ioc_type", "threat_type", "malware_family",
                            "confidence_score", "severity", "source", "hit_count",
                            "first_seen", "last_seen"]
        show = [c for c in display_ioc_cols if c in df_iocs.columns]
        st.write(f"Showing **{len(df_iocs)}** indicators")
        st.dataframe(df_iocs[show], use_container_width=True, height=440)

        # Export
        st.divider()
        col_ie1, col_ie2 = st.columns(2)
        col_ie1.download_button(
            "⬇️ Export IOCs as CSV",
            data=df_iocs[show].to_csv(index=False).encode(),
            file_name=f"iocs_{datetime.now():%Y%m%d_%H%M}.csv",
            mime="text/csv",
        )
        col_ie2.download_button(
            "⬇️ Export IOCs as JSON",
            data=df_iocs[show].to_json(orient="records", indent=2).encode(),
            file_name=f"iocs_{datetime.now():%Y%m%d_%H%M}.json",
            mime="application/json",
        )
    else:
        st.info("No IOCs found. Click **Sync Threat Feeds** in the sidebar.")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4 — Analytics Dashboard
# ═══════════════════════════════════════════════════════════════════════════════
with tab_analytics:
    st.subheader("📊 Platform Analytics & Threat Overview")

    # ── KPI Row ──────────────────────────────────────────────────────────────
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total IOCs",          get_ioc_count())
    k2.metric("Total Alerts",        get_alert_count())

    sev_dist = get_alert_severity_distribution()
    k3.metric("Critical Alerts",     sev_dist.get("critical", 0), delta_color="inverse")
    k4.metric("High Alerts",         sev_dist.get("high", 0),     delta_color="inverse")

    st.divider()

    col_chart1, col_chart2 = st.columns(2)

    # ── IOC Type Distribution (bar chart) ────────────────────────────────────
    with col_chart1:
        st.markdown("#### IOC Type Distribution")
        ioc_dist = get_ioc_type_distribution()
        if ioc_dist:
            df_ioc_dist = pd.DataFrame(
                list(ioc_dist.items()), columns=["IOC Type", "Count"]
            ).set_index("IOC Type")
            st.bar_chart(df_ioc_dist)
        else:
            st.caption("No data yet.")

    # ── Alert Severity Distribution (bar chart) ───────────────────────────────
    with col_chart2:
        st.markdown("#### Alert Severity Distribution")
        if sev_dist:
            # Order: critical → high → medium → low
            ordered_keys = ["critical", "high", "medium", "low"]
            ordered = {k: sev_dist.get(k, 0) for k in ordered_keys}
            df_sev = pd.DataFrame(
                list(ordered.items()), columns=["Severity", "Count"]
            ).set_index("Severity")
            st.bar_chart(df_sev)
        else:
            st.caption("No alert data yet.")

    # ── Daily Alert Trend (line chart) ───────────────────────────────────────
    st.markdown("#### Alert Trend — Last 7 Days")
    trend_data = get_alerts_daily_trend(days=7)
    if trend_data:
        df_trend = pd.DataFrame(trend_data).set_index("day")
        df_trend.index.name = "Date"
        st.line_chart(df_trend.rename(columns={"count": "Alerts"}))
    else:
        st.caption("Not enough data for a trend chart yet — run some correlations first.")

    # ── Top Malware Families ──────────────────────────────────────────────────
    st.markdown("#### Top Malware Families (by alert hits)")
    top_families = get_top_malware_families(limit=10)
    if top_families:
        df_fam = pd.DataFrame(top_families)
        df_fam.columns = ["Malware Family", "Alert Hits", "Max Severity"]
        st.dataframe(df_fam, use_container_width=True, hide_index=True)
    else:
        st.caption("No alert data yet.")

    # ── MITRE ATT&CK Summary ─────────────────────────────────────────────────
    st.markdown("#### MITRE ATT&CK Coverage")
    alerts_all = get_all_alerts(limit=500)
    if alerts_all:
        df_att = pd.DataFrame(alerts_all)
        if "attack_technique" in df_att.columns and df_att["attack_technique"].notna().any():
            att_counts = (
                df_att[df_att["attack_technique"].notna() & (df_att["attack_technique"] != "")]
                .groupby(["attack_technique", "attack_name"])
                .size()
                .reset_index(name="Alerts")
                .sort_values("Alerts", ascending=False)
            )
            att_counts.columns = ["Technique ID", "Technique Name", "Alert Count"]
            st.dataframe(att_counts, use_container_width=True, hide_index=True)
        else:
            st.caption("Run log correlation to populate ATT&CK data.")
    else:
        st.caption("No alerts yet.")