# SENTINEL // Security Threat Intelligence and IOC Correlation Platform

## Overview
**SENTINEL** is a high-performance, Python-based Cyber Threat Intelligence (CTI) and IOC Correlation Platform. It continuously collects Indicators of Compromise (IOCs) such as IP addresses, domains, URLs, hashes, and emails from authorized threat-intelligence feeds, normalizes and enriches them, correlates them with locally captured security logs, and provides automated containment rules and incident reports.

---

## Architecture & Features

### 1. Multi-Feed Threat Intelligence Ingestion
- **Abuse.ch ThreatFox**: Malware and C2 infrastructure indicators.
- **Abuse.ch URLhaus**: Malicious payload download URLs.
- **Abuse.ch FeodoTracker**: Active Botnet C2 IP addresses.
- **Abuse.ch MalwareBazaar**: Recent malware file hashes (MD5, SHA1, SHA256).
- **AlienVault OTX**: Pulses & indicators via REST API.

### 2. Normalization, Refanging & Enrichment
- **Refanging Engine**: Auto-corrects defanged indicators (`[.]`, `(.)`, `{.}`, `hxxp`, `[at]`).
- **Strict Validation**: RFC1918 private/loopback IP filtering, FQDN validation, URL canonicalization.
- **Enrichment Module**: Real-time GeoIP, Geographic Origin (Country/City), ISP, Organization, and Reverse DNS resolution.

### 3. Advanced Correlation Engine
- **O(1) In-Memory Matching**: High-speed lookup across tens of thousands of active IOCs.
- **CIDR Subnet Matching**: Matches individual log IPs against blacklisted network CIDR ranges (e.g. `194.26.29.0/24`).
- **Fuzzy Subdomain Matching**: Flags queries to malicious parent domains (`sub.evil.com` -> `evil.com`).
- **Structured & Unstructured Log Parsing**: Parses raw Syslog, Firewall, Web server, and Suricata/Zeek JSON events.

### 4. MITRE ATT&CK Mapping
- Maps detected threats automatically to **MITRE ATT&CK Tactics & Techniques** (e.g. *T1071 Application Layer Protocol*, *T1566 Phishing*, *T1584 Compromise Infrastructure*, *T1486 Data Encrypted for Impact*).

### 5. Automated Containment & Mini-SOAR
- 1-Click generated remediation rules for detected threats:
  - **Linux Firewall**: `iptables -A INPUT -s <IP> -j DROP`
  - **Windows Defender Firewall**: PowerShell block commands
  - **DNS Sinkhole**: `/etc/hosts` and Pi-hole entries (`0.0.0.0 <domain>`)
  - **Intrusion Detection**: Custom Suricata / Snort signature rules
  - **Proxy ACLs**: Squid proxy domain deny rules

### 6. Incident Reporting & Live Directory Ingestion
- **Incident Report Export**: Printable, executive & technical incident reports.
- **Real-Time Directory Watcher**: Automatically ingests and correlates any `.log`, `.txt`, or `.json` file dropped into the `auto_ingest/` folder.

---

## Folder Structure
```
app/
├── collectors/       # Feed connectors (ThreatFox, URLhaus, Feodo, Bazaar, OTX)
├── parsers/          # Log stream extraction & JSON/Syslog parsing
├── routes/           # FastAPI controllers (Dashboard, Alerts, IOCs, Feeds, Logs, Lookup)
├── templates/        # Jinja2 HTML templates & Dark SOC UI
├── config.py         # App configuration & .env loader
├── correlator.py     # O(1) in-memory matcher with CIDR & fuzzy domain lookups
├── enrichment.py     # GeoIP, ASN, Org, and Reverse DNS resolver
├── mitre.py          # MITRE ATT&CK framework mapping
├── remediation.py    # Automated firewall / DNS sinkhole rule generator
├── watcher.py        # Real-time directory auto-ingestion daemon
└── main.py           # Application entrypoint & lifespan
```

---

## Quickstart

### 1. Native Python Setup
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run initial threat seed (Optional if threat_intel.db already exists)
python seed_demo.py

# 3. Test correlation engine
python test_match.py

# 4. Start SENTINEL Web Platform
uvicorn app.main:app --reload
```

Open your browser at **[http://localhost:8000](http://localhost:8000)**. Default credentials:
- **Username:** `admin`
- **Password:** `changeme123`

### 2. Docker / Docker Compose Setup
```bash
docker compose up -d
```

---

## Verification & Testing
Run the built-in automated test suites:
```bash
# Test Log Correlation against demo log
python test_match.py

# Test all v2.0 enhancements (CIDR, MITRE, Enrichment, Remediation, JSON)
python test_enhancements.py
```
