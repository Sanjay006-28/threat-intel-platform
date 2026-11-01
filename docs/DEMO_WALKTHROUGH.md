# SENTINEL // Live Demonstration & Walkthrough Guide

## Scenario: Operation "DarkBeacon" Multi-Stage Intrusion Walkthrough

This guide provides a structured, live demonstration script for presentations, client demos, or academic evaluation. It walks through an APT intrusion targeting corporate host `WS-FINANCE-04` (`192.168.1.50`).

> [!NOTE]
> This is a controlled simulation using synthetic logs and indexed threat intelligence indicators. No live malicious infrastructure is contacted.

---

## 1. Pre-Demo Verification Checklist
Before starting the demo:
- [ ] Confirm Python virtual environment is activated (`.\.venv\Scripts\Activate.ps1`).
- [ ] Verify test suite passes (`python tests/test_match.py`).
- [ ] Ensure database backup exists (`python manage_backup.py backup`).
- [ ] Verify `auto_ingest/` is empty (except `.gitkeep`).

---

## 2. Stage-by-Stage Demonstration Walkthrough

### Phase 1: Platform Startup & Authentication
1. **Launch Platform:** Double-click `start.bat`.
   - *Point out:* Uvicorn starts on loopback `127.0.0.1`, binds dynamically to an available port, initializes WAL PRAGMAs, and automatically launches the browser.
2. **Access Control:** Try navigating directly to `http://localhost:8000/alerts`.
   - *Point out:* `AuthMiddleware` blocks unauthenticated access and issues an HTTP 303 redirect to `/login`.
3. **Login:** Submit administrator credentials (`admin` / `SentinelSOC#2026!`).
   - *Point out:* Secure bcrypt hash verification; rate-limiting defense against brute-force attacks; audit logging of the successful session.

---

### Phase 2: Threat Intelligence Repository Review
1. **Dashboard Metrics (`/`):**
   - *Point out:* The 39,522 loaded indicators, severity distribution doughnut chart, and real-time geographic distribution map.
2. **Threat Feed Connectors (`/feeds`):**
   - *Point out:* The 5 automated feeds (ThreatFox, URLhaus, FeodoTracker, MalwareBazaar, AlienVault OTX) with configured 6-hour sync intervals and run history.
3. **IOC Exploration (`/iocs`):**
   - *Action:* In the search bar, type `emotet` or `rat`.
   - *Point out:* Server-side pagination, confidence ratings (0–100), severity badges, and source attributions.

---

### Phase 3: Automated Ingestion of Attack Scenario
1. **Trigger Ingestion:** Open PowerShell and copy the demonstration scenario into `auto_ingest/`:
   ```powershell
   Copy-Item demo_logs\master_apt_demonstration.log auto_ingest\
   ```
2. **Observe Terminal / Directory:**
   - *Point out:* Watchdog detects the file creation, tests read-handle stability, ingests and correlates events in 500-line batches, and renames the file to `master_apt_demonstration.log.processed`.

---

### Phase 4: Alert Investigation & Correlation Walkthrough
Navigate to **Alerts** (`/alerts`):
1. **Review Intrusion Timeline:**
   - **Stage 1 (Phishing & Recon):** `attacker@phishing-bank-login.top` & DNS query for `login.phishing-bank-login.top`.
   - **Stage 2 (Payload Delivery):** HTTP GET request to `http://evil-malware-download.xyz/payload.exe`.
   - **Stage 3 (Execution & Hashes):** MD5 `44d88612fea8a8f36de82e1278abb02f` & SHA256 `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`.
   - **Stage 4 (C2 Beaconing):** Outbound connections to `185.220.101.5` & CIDR block `194.26.29.112`.
   - **Stage 5 (RAT Channel):** Outbound connection to AsyncRAT C2 `91.92.251.103:8808`.
2. **Drill Down into Critical Alert (e.g. `185.220.101.5`):**
   - *Action:* Click **Inspect**.
   - *Inspect Evidence:* View the raw log line, extraction timestamp, and originating asset (`192.168.1.50`).
   - *Inspect Network Context:* Geolocation, ISP, ASN, and PTR records retrieved over TLS HTTPS (`https://ipwho.is/`).
   - *Inspect MITRE ATT&CK:* Automated mapping to **T1071** (*Application Layer Protocol*) and **T1584** (*Compromise Infrastructure*).
   - *Inspect Scoring:* View explainable model breakdown showing confidence, multi-feed corroborate boost, and occurrence frequency.

---

### Phase 5: Incident Case Management & Containment
1. **Assign to Incident Case:**
   - In the alert decision card, assign the alert to an incident (e.g. create case *Case #1: Operation DarkBeacon Workstation Intrusion*).
2. **Review Containment Advisory:**
   - Click "Remediation Rules".
   - *Point out:* Copy-paste ready Windows Firewall rules with unique display names (`SENTINEL-Block-Outbound-...`), Linux `iptables` drop rules, DNS sinkhole entries, and Suricata drop rules. Mention syntax validation that eliminates shell command injection.
3. **Demonstrate False-Positive Suppression:**
   - Explain that changing status to "False Positive" updates the local record, while selecting "Suppress Indicator Globally" adds it to the Whitelist and deactivates the IOC to prevent alert fatigue.

---

### Phase 6: Reporting & Threat Intelligence Sharing
1. **Generate Incident Report:**
   - On the alert page, click "Printable Report".
   - *Point out:* Clean, formatted printable report with executive summary, raw evidence, forensic network context, and signature sign-offs.
2. **Export STIX 2.1 Threat Intelligence:**
   - Navigate to `/settings` or `/api/stix/export`.
   - *Action:* Download `sentinel_stix21_bundle.json`.
   - *Point out:* OASIS STIX 2.1 compliant JSON format ready for ingest by external SIEMs, TIPs, or sharing with ISACs.
3. **Review Audit Logs (`/audit-logs`):**
   - *Point out:* Immutable audit trail capturing analyst logins, alert modifications, status transitions, and whitelist actions.

