# SENTINEL // Visual Capture Guide for Portfolio & Research Presentation

This directory is designated for storing high-resolution screenshots of the running SENTINEL platform. Below is the list of 10 essential screenshots to capture during the demonstration walkthrough:

---

### Screenshot 1: Executive SOC Dashboard (`/`)
- **Route:** `http://localhost:8000/`
- **Focus:**
  - KPI counter tiles: 39,522 Active IOCs, Total Alerts, High/Critical Hits, Active Cases.
  - Interactive Chart.js charts: Severity Doughnut and Ingestion Volume Line Chart.
  - Interactive Leaflet Threat Map visualizing global threat origin points.
- **Recommended File Name:** `01_soc_executive_dashboard.png`

---

### Screenshot 2: Threat Intelligence Feeds Console (`/feeds`)
- **Route:** `http://localhost:8000/feeds`
- **Focus:**
  - Active cards for the 5 threat feed connectors: ThreatFox, URLhaus, FeodoTracker, MalwareBazaar, and AlienVault OTX.
  - Sync execution history table showing record counts, success statuses, and run timestamps.
- **Recommended File Name:** `02_threat_intel_feeds_console.png`

---

### Screenshot 3: Paginated IOC Repository & Filter (`/iocs`)
- **Route:** `http://localhost:8000/iocs?q=emotet`
- **Focus:**
  - Server-side paginated indicator table.
  - Search filter demonstrating keyword matching (`emotet`).
  - Indicator badges: Type (IPv4, CIDR, Domain, SHA256), Confidence ratings, and feed attribution pills.
- **Recommended File Name:** `03_ioc_repository_search.png`

---

### Screenshot 4: Alerts Overview & Multi-Endpoint Table (`/alerts`)
- **Route:** `http://localhost:8000/alerts`
- **Focus:**
  - Real-time alerts generated from log correlation.
  - Multi-endpoint separation showing distinct internal assets (`192.168.1.50`, `192.168.1.88`).
  - MITRE ATT&CK tactic pills and inline status triage dropdowns.
- **Recommended File Name:** `04_alerts_overview_table.png`

---

### Screenshot 5: Deep Alert Investigation View (`/alerts/{id}`)
- **Route:** `http://localhost:8000/alerts/1`
- **Focus:**
  - Raw Security Log Evidence code snippet.
  - Geolocation, ASN, and reverse DNS PTR details retrieved over TLS HTTPS (`https://ipwho.is/`).
  - MITRE ATT&CK Tactic and Technique mapping cards with reference links.
  - Explainable Score Breakdown showing base confidence, corroborating feeds, and occurrence frequency.
- **Recommended File Name:** `05_alert_deep_investigation.png`

---

### Screenshot 6: Passive Containment Advisory Modal
- **Trigger:** Click "Remediation Rules" on any high/critical alert.
- **Focus:**
  - Copy-paste ready rules across tabs: Windows Defender Firewall (`netsh advfirewall`), Linux `iptables`, DNS sinkholes, and Suricata/Snort signatures.
  - Unique Windows Firewall display rule naming (`SENTINEL-Block-Outbound-...`).
- **Recommended File Name:** `06_passive_containment_modal.png`

---

### Screenshot 7: Incident Case Management Console (`/incidents`)
- **Route:** `http://localhost:8000/incidents`
- **Focus:**
  - Active investigation cases list with status badges (`Open`, `Contained`, `Resolved`).
  - Incident details view demonstrating multi-alert aggregation and analyst investigation notes.
- **Recommended File Name:** `07_incident_case_management.png`

---

### Screenshot 8: False-Positive Suppression Confirmation
- **Trigger:** Alert Decision Card on `/alerts/{id}`.
- **Focus:**
  - Selecting "False Positive" status with the confirmation checkbox "Suppress Indicator Globally".
  - Whitelist integration preventing alert storms.
- **Recommended File Name:** `08_false_positive_suppression.png`

---

### Screenshot 9: Printable Incident Investigation Report (`/alerts/{id}/report`)
- **Route:** `http://localhost:8000/alerts/1/report`
- **Focus:**
  - Executive report layout optimized for printing / PDF presentation.
  - Complete evidence table, MITRE ATT&CK context, remediation steps, and analyst signature lines.
- **Recommended File Name:** `09_printable_incident_report.png`

---

### Screenshot 10: Immutable SOC Audit Trail (`/audit-logs`)
- **Route:** `http://localhost:8000/audit-logs`
- **Focus:**
  - Complete chronological audit log of analyst actions (logins, alert decisions, whitelist updates, case transitions).
  - Client IP addresses and exact timestamps.
- **Recommended File Name:** `10_soc_audit_trail.png`

