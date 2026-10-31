# SENTINEL // Cyber Threat Intelligence (CTI) & IOC Correlation Platform

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-FastAPI-green.svg)](https://fastapi.tiangolo.com/)
[![Database](https://img.shields.io/badge/database-SQLite_WAL-orange.svg)](https://www.sqlite.org/wal.html)
[![STIX](https://img.shields.io/badge/interop-STIX_2.1-red.svg)](https://oasis-open.github.io/cti-documentation/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)

## 1. Overview
**SENTINEL** is an advanced, high-performance Cyber Threat Intelligence (CTI) and Security Operations Center (SOC) correlation platform engineered in Python. It automatically aggregates Indicators of Compromise (IOCs) from premier global threat feeds, normalizes and enriches them, correlates internal security logs and live host network telemetry in real-time, generates deduplicated alerts, maps adversary behaviors to the MITRE ATT&CK framework, coordinates incident investigations, and provides safe, injection-proof passive containment recommendations.

Designed as an analyst-centric local SOC workstation, SENTINEL combines in-memory $O(1)$ correlation performance with SQLite Write-Ahead Logging (WAL) concurrency to process high-throughput security event streams without external heavy infrastructure.

---

## 2. Documentation Suite

Full technical, architectural, and operational documentation is available in the `docs/` directory:

| Document | Description |
|---|---|
| [**Project Overview**](docs/PROJECT_OVERVIEW.md) | High-level summary of capabilities, problem statement, threat feeds, and deployment model. |
| [**System Architecture**](docs/SYSTEM_ARCHITECTURE.md) | In-depth architectural blueprint, data flow diagrams, schema relationships, and algorithmic models. |
| [**Installation Guide**](docs/INSTALLATION_GUIDE.md) | Step-by-step native Windows 10/11 and Docker deployment, dependencies, and environment setup. |
| [**User Guide**](docs/USER_GUIDE.md) | SOC analyst operations manual for alerts, cases, IOC queries, whitelist management, and reports. |
| [**Testing Report**](docs/TESTING_REPORT.md) | Complete validation logs, test suite breakdown, benchmark measurements, and edge-case results. |
| [**Backup & Recovery Guide**](docs/BACKUP_RECOVERY_GUIDE.md) | Atomic database backup, automatic rotation retention, and disaster recovery procedures. |
| [**Demo Walkthrough**](docs/DEMO_WALKTHROUGH.md) | 5-stage end-to-end controlled demonstration scenario (*Operation DarkBeacon*) for live presentation. |
| [**Screenshots Guide**](docs/screenshots/README.md) | 10-screen visual documentation guide with high-resolution screenshot captions. |

---

## 3. Architecture & Core Capabilities

```
┌─────────────────────────────────┐      ┌──────────────────────────────────┐
│ Threat Intel Feeds (External)   │      │ Security Logs & Live Telemetry   │
│  - Abuse.ch ThreatFox (C2/Mal)  │      │  - Syslog / Firewall / Web Logs  │
│  - Abuse.ch URLhaus (Payloads)  │      │  - Suricata / Zeek JSON logs     │
│  - Abuse.ch FeodoTracker (Bots) │      │  - Live Windows Netstat / DNS    │
│  - Abuse.ch MalwareBazaar (Hash)│      │  - Directory Watcher (auto_ingest)│
│  - AlienVault OTX Pulses        │      └────────────────┬─────────────────┘
└───────────────┬─────────────────┘                       │
                │                                         │
                ▼                                         ▼
   [ Normalization & Refanging ]             [ Stream Parser & Batch Committer]
   (Defang restore, RFC1918 filter)          (Regex & JSON field extractor)
                │                                         │
                ▼                                         ▼
   [ Central IOC Database ]  ◄──────────────► [ Correlation Engine ]
   (39,000+ Active Indicators)                - In-Memory O(1) Exact Match
                                              - CIDR Subnet Block Matching
                                              - Label-Bounded Subdomain Matching
                                                          │
                                                          ▼
                                             [ Alert Aggregation & Lifecycle ]
                                             - 1-Hour Time-Window Deduplication
                                             - Explainable Risk Score (0–100)
                                             - Bounded Geolocation & Reverse DNS
                                             - MITRE ATT&CK Tactic/Technique
                                                          │
                                         ┌────────────────┴────────────────┐
                                         ▼                                 ▼
                          [ Passive Containment Advisory ]      [ SOC Web Dashboard & Cases ]
                          - Windows Defender Firewall           - Incident Case Management
                          - Linux iptables Drop Rules           - Leaflet Threat Map
                          - Suricata / Snort Signatures         - STIX 2.1 Bidirectional Sync
                          - DNS Sinkhole / Proxy ACL            - SOC Audit Trails (Immutable)
```

### Key Engineering Highlights

1. **Security & Session Hardening:**
   - **Enforced Authentication:** `DEV_AUTO_LOGIN` disabled by default. Protected HTTP session cookies with 24-hour expiration (`SESSION_MAX_AGE_SECONDS=86400`).
   - **Bcrypt Password Verification:** Secure password hashing for all analyst accounts.
   - **Forced First-Login Password Change:** Rejects default credentials and requires an analyst password change before unlocking SOC routes.
   - **Brute-Force Protection:** In-memory rate limiting locks login after 5 failed attempts per IP for 15 minutes.
   - **Audit Trails:** Immutable database logging of all analyst actions: logins, whitelist additions, alert status modifications, IOC deactivations, and incident cases.
   - **Command Injection Prevention:** Remediation rule generator validates IPs, CIDRs, domains, and hashes against strict syntax and rejects shell metacharacters.

2. **Accurate Normalization & Correlation Engine:**
   - **Refanging Engine:** Auto-corrects defanged syntax (`[.]`, `(.)`, `{.}`, `hxxp://`, `hxxps://`, `[at]`).
   - **CIDR Subnet Matching:** Normalizes network ranges (`194.26.29.0/24`) and correlates individual log IPs against blacklisted network blocks.
   - **DNS Label-Boundary Subdomain Matching:** Matches subdomains (`sub.evil.com` $\rightarrow$ `evil.com`) while strictly respecting DNS boundaries to prevent partial suffix false matches (e.g., `notevil.com` does not match `evil.com`).
   - **RFC1918 Separation:** Private IPs are discarded during external feed ingestion but preserved during log parsing to identify affected internal assets.

3. **Time-Window Alert Deduplication & Scoring:**
   - **Time-Window Aggregation:** Replaces per-line alert flooding with configurable 1-hour window deduplication. Repeated hits within the window increment `hit_count` and update `last_seen` on the existing alert row.
   - **Explainable Scoring:** Bounded between 0 and 100 based on base confidence, corroborating independent feeds, indicator fidelity, and log occurrence frequency.

4. **Incident Case Management:**
   - Multi-alert grouping under formal incident cases with status tracking (`Open`, `Investigating`, `Contained`, `Resolved`, `Closed`), analyst notes, and resolution summaries.

5. **High-Performance Batch Ingestion & Watcher:**
   - **Chunked Transactions:** Ingestion processes log lines in configurable 500-event database commits, increasing throughput to over 580 events/second committed to disk and 7,900+ lines/second in-memory matching.
   - **File-Lock Resilient Watcher:** Detects file write completion via size stability and read-lock tests before processing dropped files in `auto_ingest/`.

6. **Automated Threat Intelligence & Lifecycle:**
   - **APScheduler Daemon:** Automatically synchronizes threat feeds every 6 hours in the background.
   - **Automated IOC Expiration:** Daily deactivation of indicators past TTL (`IOC_TTL_DAYS=30`) without deleting historical forensics.
   - **IOC Repository Interface:** Server-side pagination, search by indicator value/tag, and manual IOC creation.

7. **Threat Enrichment & MITRE ATT&CK Mapping:**
   - **Bounded TTL Cache:** Prevents memory leaks and third-party rate-limit delays. Internal RFC1918 IPs resolve locally without external WAN queries.
   - **Precise MITRE ATT&CK Mapping:** Maps threat tags to official technique IDs, tactics, and external reference links.

8. **Interoperability & Passive Containment:**
   - **STIX 2.1 Bidirectional Support:** Export active IOCs as compliant STIX 2.1 bundles, and import external STIX 2.1 bundles into the database.
   - **Passive Containment Advisory:** Generates copy-paste rules for iptables, Windows Firewall (unique display names), DNS sinkholes, and Suricata/Snort.

---

## 4. Directory Structure

```
threat_intel_platform/
├── app/
│   ├── collectors/       # Feed connectors (ThreatFox, URLhaus, Feodo, Bazaar, OTX, runner)
│   ├── parsers/          # Stream parsing (Syslog, CLF, Firewall, Suricata/Zeek JSON)
│   ├── routes/           # FastAPI routers (Dashboard, Alerts, Incidents, IOCs, Feeds, Logs, Settings, Auth)
│   ├── templates/        # Jinja2 templates (Bootstrap 5 Dark SOC UI)
│   ├── static/           # CSS, JS, and image assets
│   ├── audit.py          # Centralized audit logging utility
│   ├── config.py         # Configuration settings & environment variables
│   ├── correlator.py     # O(1) in-memory matcher with CIDR & label-bounded domain lookups
│   ├── database.py       # SQLite connection with WAL mode & automated schema migrations
│   ├── enrichment.py     # Bounded TTL cached GeoIP, ASN, Org & reverse DNS resolver
│   ├── main.py           # FastAPI entrypoint, lifespan daemon & authentication middleware
│   ├── mitre.py          # MITRE ATT&CK framework mapping
│   ├── models.py         # SQLAlchemy ORM models (IOC, Alert, Incident, LogFile, Whitelist, AuditLog)
│   ├── normalizer.py     # Strict IOC validation, refanging & CIDR parsing
│   ├── notifications.py  # Discord / Slack / HTTP webhook dispatcher
│   ├── remediation.py    # Injection-safe containment rule generator
│   ├── scoring.py        # Explainable 0-100 risk scoring model
│   ├── stix.py           # OASIS STIX 2.1 export & import parser
│   └── watcher.py        # Directory auto-ingestion daemon with file-lock recovery
├── auto_ingest/          # Monitored directory for auto-correlating dropped log files
├── demo_logs/            # Curated multi-vector test security logs (Firewall, Netstat, DNS, Suricata, Zeek, APT)
├── docs/                 # Full technical and operational documentation suite
│   ├── PROJECT_OVERVIEW.md
│   ├── SYSTEM_ARCHITECTURE.md
│   ├── INSTALLATION_GUIDE.md
│   ├── USER_GUIDE.md
│   ├── TESTING_REPORT.md
│   ├── BACKUP_RECOVERY_GUIDE.md
│   ├── DEMO_WALKTHROUGH.md
│   └── screenshots/
├── collect_laptop_logs.py# Live host outbound netstat & DNS client cache collector
├── demo_security.log     # Curated multi-vector test security log
├── Dockerfile            # Container image specification
├── docker-compose.yml    # Container orchestration file
├── manage_backup.py      # SQLite WAL online backup and disaster recovery utility
├── requirements.txt      # Python dependencies
├── run.py                # Server launcher with dynamic port binding & auto-browser launch
├── start.bat             # 1-Click Windows launch script
├── test_comprehensive_suite.py # Automated functional validation & benchmark suite
├── test_enhancements.py  # Architectural enhancement test suite
├── test_match.py         # Multi-threat log matching test
└── test_strict_verification.py # 17-point independent verification & 50,000-line WAL stress benchmark
```

---

## 5. Quickstart Guide

### Option A: Local Windows / Python Environment (Recommended)

1. **Activate Virtual Environment:**
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

2. **Verify Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment:**
   Copy `.env.example` to `.env` and set your preferred credentials and parameters:
   ```powershell
   Copy-Item .env.example .env
   ```

4. **Launch SENTINEL Platform:**
   ```bash
   python run.py
   # Or simply double-click start.bat
   ```

5. **Access Web Console:**
   - URL: **[http://localhost:8000](http://localhost:8000)** (or automatically assigned alternative port if 8000 is occupied).
   - Sign in with your administrator credentials configured in `.env`.
   - *(Note: If the application detects default credentials, it strictly enforces a mandatory password change on first login before granting access to SOC views)*.

---

### Option B: Docker / Docker Compose

1. **Build and Launch Container:**
   ```bash
   docker compose up -d
   ```

2. **Inspect Container Status:**
   ```bash
   docker compose ps
   docker compose logs -f
   ```

3. **Access Web Console:**
   - Browse to **[http://localhost:8000](http://localhost:8000)**.

---

## 6. Demonstration & Controlled Test Scenarios

SENTINEL provides a dedicated collection of safe, controlled sample logs located in `demo_logs/`:
- **`sample_firewall.log`**: iptables/pfSense firewall blocks with malicious C2 connections (`185.220.101.5`) and blacklisted CIDR subnets (`194.26.29.112`).
- **`sample_windows_netstat.log`**: Windows Event 5156 and 4688 logs showing infected process hashes and outbound PowerShell connections.
- **`sample_dns_queries.log`**: DNS query records for phishing domains (`phishing-bank-login.top`).
- **`sample_suricata_eve.json`**: Suricata EVE NIDS telemetry with HTTP and flow detections.
- **`sample_zeek_conn.log`**: Zeek (Bro) connection flow logs.
- **`master_apt_demonstration.log`**: Unified 5-stage APT intrusion scenario (*Operation DarkBeacon*: phishing, ingress payload download, hash execution, C2 beaconing, and AsyncRAT encrypted session).

To demonstrate real-time directory ingestion:
```powershell
# Copy sample scenario into the auto_ingest directory
Copy-Item demo_logs\master_apt_demonstration.log auto_ingest\
# The platform detects, processes, alerts, and renames the file to .processed automatically
```

For the complete presentation script, refer to [**`docs/DEMO_WALKTHROUGH.md`**](docs/DEMO_WALKTHROUGH.md).

---

## 7. Database Backup & Disaster Recovery

SENTINEL includes an online SQLite backup utility utilizing SQLite's WAL checkpointing and atomic backup API:

```bash
# 1. Create point-in-time database backup (with automatic retention rotation)
python manage_backup.py backup

# 2. Restore database from a backup
python manage_backup.py restore --file sentinel_backup_YYYYMMDD_HHMMSS.db

# 3. Verify database integrity
python manage_backup.py verify
```

---

## 8. Automated Verification & Testing

SENTINEL includes comprehensive test suites covering all architectural layers:

```bash
# 1. Run Complete 17-Point Independent Verification & 50,000-Line Benchmark
python test_strict_verification.py

# 2. Run Comprehensive Functional & Scoring Test Suite
python test_comprehensive_suite.py

# 3. Test Core Threat Intel Enhancements Suite
python test_enhancements.py

# 4. Test Multi-Threat Match Engine against Demo Log
python test_match.py
```

### Measured Performance Benchmarks
- **In-Memory Matching Throughput:** `7,976 lines/second` (125.4 $\mu$s/line).
- **End-to-End SQLite WAL Ingestion:** `585 events/second` committed to disk across 50,000 events.
- **Exact Hash/IP Correlation Latency:** `8–12 microseconds` per lookup across 39,522 IOCs.

---

## 9. Operational Troubleshooting

| Symptom | Potential Cause | Solution |
|---|---|---|
| **Port 8000 already in use** | Another service running on port 8000 | `run.py` dynamically probes and binds to port 8080 or 8001 automatically. Check console output for the assigned URL. |
| **Watcher does not pick up files** | File write still in progress or file locked | The watcher verifies size stability over an 8-second window. Ensure file copying has finished; supported extensions are `.log`, `.txt`, `.json`. |
| **GeoIP enrichment shows Unknown** | Offline host or rate-limited third-party endpoint | Place MaxMind `GeoLite2-City.mmdb` in project root for local zero-network lookups. RFC1918 IPs resolve locally as Intranet. |
| **Database is locked error** | Long external transaction | WAL mode (`PRAGMA journal_mode=WAL`) and `busy_timeout=15000` handle concurrent reads. Use 500-event batch sizes during custom log ingestion. |

---

## 10. License & Ethical Disclaimer
This project is licensed under the MIT License. SENTINEL is designed strictly for authorized cyber defense, security monitoring, and academic educational research. Never execute intrusive scans or correlation on networks without explicit authorization.
