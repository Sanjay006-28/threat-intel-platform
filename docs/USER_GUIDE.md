# SENTINEL // SOC Analyst User Guide

## 1. Authentication & Session Security
1. **Accessing the Console:** Open your browser to `http://localhost:8000`. Unauthenticated requests are redirected to `/login`.
2. **First Login Enforcement:** If the administrator account is using the default installation password (`changeme123`), the platform redirects to `/change-password`. Navigation to other pages is restricted until a password of $\ge 8$ characters is submitted.
3. **Brute Force Protection:** 5 consecutive failed login attempts lock out the client IP for 15 minutes.
4. **Session Timeout:** Sessions expire after 24 hours of inactivity (`SESSION_MAX_AGE_SECONDS=86400`).

---

## 2. Executive Dashboard Overview (`/`)
The SOC Dashboard presents high-level operational metrics:
- **Metric Badges:** Active Threat Indicators (39,522), Total Correlated Alerts, High/Critical Hits, Active Incidents.
- **Visual Trends:** Alert Severity breakdown (Chart.js doughnut) and Log Ingestion Volume timeline (Chart.js line graph).
- **Threat Map:** Geolocation of active external threat infrastructure detected in your environment.
- **Quick Links:** One-click shortcuts for log uploads, manual IOC creation, and STIX 2.1 downloads.

---

## 3. Threat Intelligence Repository (`/iocs`)
- **Searching Indicators:** Search across values, descriptions, or threat tags (e.g. `emotet`, `qakbot`, `c2`).
- **Filtering:** Filter by IOC Type (`IPv4`, `CIDR`, `Domain`, `URL`, `SHA256`, `MD5`) and Status (`Active` vs `Inactive`).
- **Manual Indicator Addition:** Click "Add Indicator" to manually submit high-fidelity indicators with confidence ratings and descriptions.
- **Indicator Lifecycle:** Stale indicators past 30 days are deactivated automatically. Re-reporting by threat feeds reactivates indicators and refreshes their TTL.

---

## 4. Security Log Ingestion
SENTINEL supports two ingestion workflows:

### A. Automatic Monitored Directory (`auto_ingest/`)
1. Place security log files (`.log`, `.txt`, `.json`) into the `auto_ingest/` directory.
2. The background Watchdog daemon detects the file, verifies that write handles are closed, parses artifacts, correlates hits, commits transactions in 500-line batches, and renames the file to `<name>.processed`.

### B. Web Console Upload (`/logs/upload`)
1. Navigate to "Log Ingestion" in the navigation bar.
2. Select your log file and click "Upload & Correlate".
3. The platform streams the file line by line without excessive RAM usage.

---

## 5. Alert Investigation & Triage (`/alerts`)
- **Alert Triage:** Review incoming alerts sorted by detection time and severity.
- **Multi-Endpoint Isolation:** Separate compromised endpoints contacting the same external indicator appear as distinct alerts.
- **Deep Investigation View (`/alerts/{id}`):**
  - **Raw Evidence:** Inspect the exact original log line that triggered the alert.
  - **Network & GeoIP Context:** Review origin country, city, Autonomous System (ASN), ISP, and reverse DNS PTR records retrieved via encrypted TLS HTTPS (`https://ipwho.is/`).
  - **MITRE ATT&CK Context:** Review mapped Tactics and Techniques with direct reference links.
  - **Explainable Score Breakdown:** Inspect how the 0–100 risk score was derived (Base Confidence $\times$ Multi-Feed Corroboration $\times$ Indicator Fidelity $+$ Occurrence Frequency).
- **False-Positive Suppression Workflow:**
  - Setting status to "False Positive" only updates that specific alert.
  - Checking the confirmation box "Suppress Indicator Globally" adds the value to the Whitelist and deactivates the IOC to prevent future alerts across the organization.

---

## 6. Incident Case Management (`/incidents`)
- **Creating a Case:** Navigate to `/incidents` $\rightarrow$ "New Incident Case" (title, severity, description).
- **Associating Alerts:** In the Alert Detail view, select the incident from the "Assign Incident" dropdown.
- **Case Progression:** Track status across standard SOC phases: `Open` $\rightarrow$ `Investigating` $\rightarrow$ `Contained` $\rightarrow$ `Resolved` $\rightarrow$ `Closed`.
- **Case Evidence Audit:** All associated alerts, indicators, affected internal endpoints, and analyst notes appear aggregated on the incident details page.

---

## 7. Passive Containment Advisory
Inside any Alert Detail view or via the shield button on the alerts table:
- **Windows Defender Firewall:** Copy-paste `netsh advfirewall` blocking rule with a unique rule display name.
- **Linux iptables:** Copy-paste `iptables -A INPUT / OUTPUT -j DROP` rule.
- **Suricata / Snort:** Pre-formatted NIDS drop rule with unique SID.
- **DNS Sinkhole:** Unbound / BIND null-route configuration for malicious domains.
- **Security Validation:** All containment rule generators strictly validate input parameters to prevent command injection.

---

## 8. Incident Reporting & STIX 2.1 Sharing
- **Printable HTML Incident Report:** Click "Printable Report" on any alert (`/alerts/{id}/report`) for a clean, formal investigation summary suitable for PDF export or executive briefings.
- **OASIS STIX 2.1 Export:** Download all active indicators as a STIX 2.1 JSON bundle from `/api/stix/export` or the Settings page.

