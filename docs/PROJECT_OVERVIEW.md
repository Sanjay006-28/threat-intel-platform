# SENTINEL // Project Overview

## 1. Executive Summary
**SENTINEL** is an advanced, high-performance Cyber Threat Intelligence (CTI) and Indicators of Compromise (IOC) Correlation Platform engineered in Python. It serves as a specialized Security Operations Center (SOC) investigation suite tailored for a single security analyst operating on a dedicated Windows workstation or small SOC environment.

SENTINEL bridges the gap between raw, overwhelming external threat feeds and internal security event monitoring. It collects threat indicators from premier threat intelligence providers, normalizes and validates them into strict data models, correlates incoming host and network logs in real-time, aggregates alerts within asset-aware time windows, enriches threats with encrypted geolocation and MITRE ATT&CK mappings, coordinates incident cases, and generates passive containment advisories.

---

## 2. Problem Statement
Modern SOC analysts face three critical operational bottlenecks:

1. **Indicator Overload & Data Heterogeneity:** Global threat feeds deliver millions of indicators in disparate, non-standard formats (CSV, JSON, plain text, defanged strings, CIDR blocks). Manual parsing and cross-referencing is error-prone and unscalable.
2. **Alert Fatigue & Duplicate Flooding:** Conventional log monitors generate a distinct alert for every individual log line matching an indicator. When an infected endpoint beacons every few seconds, the analyst is inundated with thousands of redundant alerts, obscuring unrelated compromises.
3. **Investigation Fragmentation:** Correlating an alert to adversary tactics (MITRE ATT&CK), looking up origin geolocation, creating containment rules, tracking cases, and exporting intelligence to industry standards (STIX 2.1) traditionally requires switching between multiple detached tools.

---

## 3. Project Objectives
SENTINEL was engineered to solve these challenges through four foundational objectives:

1. **Automated Intelligence Harvesting & Normalization:** Continuously ingest indicators from top-tier providers (Abuse.ch ThreatFox, URLhaus, FeodoTracker, MalwareBazaar, AlienVault OTX), safely refang obfuscated syntax (`hxxp`, `[.]`, `[at]`), and enforce a 30-day indicator lifecycle with stale indicator deactivation and re-report refreshing.
2. **High-Throughput Sub-Millisecond Correlation:** Match incoming logs against over 39,000 indexed IOCs in memory using exact $O(1)$ lookups, CIDR subnet matching, and DNS label-bounded subdomain matching at throughputs exceeding 7,000 lines/second.
3. **Asset-Aware Deduplication & Explainable Scoring:** Group repeated hits from the same asset into 1-hour time windows using deterministic keys (`ioc-{id}-ep-{endpoint}-bucket-{time}`), preventing alert flooding while isolating distinct compromised endpoints, backed by a 0–100 explainable risk score.
4. **Unified Analyst Workflow:** Provide a single-pane-of-glass dark SOC console for triage, encrypted HTTPS GeoIP enrichment, automated MITRE ATT&CK mapping, case management, passive containment rule generation (Windows Firewall, iptables, Snort, DNS sinkholes), printable reports, and OASIS STIX 2.1 JSON exchange.

---

## 4. Key Architectural Highlights
- **Persistent Backend:** SQLite 3 utilizing Write-Ahead Logging (`PRAGMA journal_mode=WAL`), normalized commits (`PRAGMA synchronous=NORMAL`), and high concurrency timeouts (`busy_timeout=15000`).
- **Asynchronous Web Framework:** FastAPI running on Uvicorn ASGI server with dynamic port probing (8000 $\rightarrow$ 8080 $\rightarrow$ 8001).
- **Security Hardening:** Bcrypt password hashing, brute-force IP rate limiting (5 attempts / 15-minute lockout), forced first-login password resets on default credentials, local loopback binding (`127.0.0.1`), and immutable audit logging.
- **Privacy Protections:** All external GeoIP enrichment routes through encrypted TLS (`https://ipwho.is/`). Internal private RFC1918 / loopback IPs are resolved locally without WAN disclosure.
- **Automated Directory Ingestion:** Background Watchdog daemon continuously monitoring `./auto_ingest` with file write-lock stability verification.

