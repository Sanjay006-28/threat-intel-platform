import sys
import os
import time
import json
import ipaddress
from datetime import datetime, timezone, timedelta

# Ensure workspace is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import Base, IOC, IOCSource, Feed, FeedRun, LogFile, LogEvent, Alert, Whitelist, Incident, AuditLog

TEST_COMP_DB = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_comprehensive_isolated.db"))
if os.path.exists(TEST_COMP_DB):
    try: os.remove(TEST_COMP_DB)
    except Exception: pass

test_engine = create_engine(f"sqlite:///{TEST_COMP_DB}", connect_args={"check_same_thread": False})
Base.metadata.create_all(bind=test_engine)
TestSession = sessionmaker(bind=test_engine)
db = TestSession()

# Seed isolated test indicators for suite tests
for idx, val in enumerate(["185.220.101.5", "evil-malware-download.xyz", "phishing-bank-login.top", "44d88612fea8a8f36de82e1278abb02f", "194.26.29.112"]):
    db.add(IOC(type="ipv4" if "." in val and not "/" in val and not "xyz" in val and not "top" in val else "domain", value=val, confidence=80, is_active=True))
db.commit()

from app.normalizer import refang, detect_and_normalize
from app.scoring import calculate_score, explain_score, get_severity
from app.correlator import Correlator
from app.remediation import generate_remediation_rules, validate_ioc_for_remediation
from app.mitre import get_mitre_mapping
from app.stix import export_to_stix21, import_stix21_bundle
from app.routes.logs import ingest_and_correlate_stream
from app.collectors.runner import expire_stale_iocs
from app.audit import log_audit

print("=" * 70, flush=True)
print("  SENTINEL COMPREHENSIVE TEST & VALIDATION SUITE", flush=True)
print("=" * 70, flush=True)

# -------------------------------------------------------------
# 1. UNIT TESTING: NORMALIZATION & REFANGING
# -------------------------------------------------------------
print("\n[TEST 1] Testing IOC Refanging & Normalization...", flush=True)

# 1.1 Refanging
assert refang("hxxp://evil[.]com/bad") == "http://evil.com/bad"
assert refang("hxxps://malware(.)org/bin") == "https://malware.org/bin"
assert refang("user[at]phish{.}net") == "user@phish.net"
print("  [+] Refanging logic passed (hxxp, [.] (.) {.} [at]).", flush=True)

# 1.2 CIDR Subnet Detection
t, v = detect_and_normalize("194.26.29.0/24")
assert t == "cidr" and v == "194.26.29.0/24", f"CIDR failed: {t}, {v}"
t_v6, v_v6 = detect_and_normalize("2001:db8::/32")
assert t_v6 == "cidr", f"IPv6 CIDR failed: {t_v6}"
print("  [+] CIDR normalization passed (IPv4 and IPv6).", flush=True)

# 1.3 URL Normalization (canonicalization)
t, v = detect_and_normalize("HxxP://EVIL.com:8080/Path/To/Payload.EXE?key=1#frag")
assert t == "url" and "evil.com:8080" in v and "/Path/To/Payload.EXE" in v and "#frag" not in v
print("  [+] URL canonicalization passed (preserves case-sensitive path, strips fragment).", flush=True)

# 1.4 Domain Normalization & Label Validation
t, v = detect_and_normalize("MALICIOUS-C2.RU")
assert t == "domain" and v == "malicious-c2.ru"
t_inv, v_inv = detect_and_normalize("invalid..domain..com")
assert t_inv is None and v_inv is None
print("  [+] Domain validation passed (lowercasing, label check, invalid rejection).", flush=True)

# 1.5 Hash Validation
t, v = detect_and_normalize("44D88612FEA8A8F36DE82E1278ABB02F")
assert t == "md5" and v == "44d88612fea8a8f36de82e1278abb02f"
t, v = detect_and_normalize("275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F")
assert t == "sha256" and v == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
print("  [+] Cryptographic hash validation passed (MD5 & SHA256 lowercasing).", flush=True)

# 1.6 RFC1918 Private IP handling
t_feed, _ = detect_and_normalize("192.168.1.1", is_feed_ioc=True)
assert t_feed is None, "Private IP should be rejected for feed IOC!"
t_log, v_log = detect_and_normalize("192.168.1.1", is_feed_ioc=False)
assert t_log == "ipv4" and v_log == "192.168.1.1", "Private IP should be kept for log parsing!"
print("  [+] RFC1918 separation passed (rejected for feeds, preserved for log events).", flush=True)

# -------------------------------------------------------------
# 2. UNIT TESTING: THREAT SCORING & SEVERITY BOUNDARIES
# -------------------------------------------------------------
print("\n[TEST 2] Testing Threat Scoring & Severity Boundaries...", flush=True)

# Test boundary conditions
assert get_severity(0) == "low"
assert get_severity(44) == "low"
assert get_severity(45) == "medium"
assert get_severity(69) == "medium"
assert get_severity(70) == "high"
assert get_severity(84) == "high"
assert get_severity(85) == "critical"
assert get_severity(100) == "critical"
print("  [+] Severity boundary mappings verified (0, 44, 45, 69, 70, 84, 85, 100).", flush=True)

score_single = calculate_score(ioc_confidence=50, source_count=1, ioc_type="ipv4", hit_count=1)
assert score_single == 50

score_multi = calculate_score(ioc_confidence=75, source_count=3, ioc_type="sha256", hit_count=5)
assert score_multi == 100, f"Expected 100 clamped, got {score_multi}"

explanation = explain_score(ioc_confidence=70, source_count=2, ioc_type="url", hit_count=3)
assert explanation["final_score"] == 89
assert explanation["severity"] == "critical"
print(f"  [+] Explainable score model passed: Final Score {explanation['final_score']} ({explanation['severity']}).", flush=True)

# -------------------------------------------------------------
# 3. UNIT TESTING: REMEDIATION RULE INJECTION SAFETY
# -------------------------------------------------------------
print("\n[TEST 3] Testing Remediation Command Injection Defense...", flush=True)

valid_ip_rules = generate_remediation_rules("ipv4", "198.51.100.25", alert_id=42)
assert valid_ip_rules["is_valid"] == True
assert "SENTINEL-Block-Inbound-42-198.51.100.25" in valid_ip_rules["windows_firewall"]
assert "SENTINEL-Block-Outbound-42-198.51.100.25" in valid_ip_rules["windows_firewall"]
assert "sudo iptables -A INPUT -s 198.51.100.25 -j DROP" in valid_ip_rules["iptables"]
assert "sid:1000042" in valid_ip_rules["suricata_snort"]
print("  [+] Safe Windows Firewall unique display names and iptables rules generated.", flush=True)

bad_ip_rules = generate_remediation_rules("ipv4", "198.51.100.25; rm -rf /; `whoami`", alert_id=43)
assert bad_ip_rules["is_valid"] == False
assert bad_ip_rules["iptables"] is None
assert "failed strict validation" in bad_ip_rules["validation_error"]
print("  [+] Command injection inputs strictly rejected without generating commands.", flush=True)

# -------------------------------------------------------------
# 4. CORRELATION ENGINE: EXACT, CIDR, SUBDOMAIN & DEDUPLICATION
# -------------------------------------------------------------
print("\n[TEST 4] Testing Correlation Engine Matching & Deduplication...", flush=True)

correlator = Correlator(db)
test_net = ipaddress.ip_network("203.0.113.0/24")
test_cidr_ioc = IOC(id=99991, value="203.0.113.0/24", type="cidr", confidence=85)
correlator.cidr_networks.append((test_net, test_cidr_ioc))

test_domain_ioc = IOC(id=99992, value="malicious-c2.net", type="domain", confidence=90)
correlator.exact_matches["malicious-c2.net"] = test_domain_ioc
correlator.domains.add("malicious-c2.net")

# 4.1 Subdomain matching with DNS label boundaries
sub_hit = correlator._fuzzy_domain_lookup("api.telemetry.malicious-c2.net")
assert sub_hit is not None and sub_hit.value == "malicious-c2.net"
fake_sub = correlator._fuzzy_domain_lookup("notmalicious-c2.net")
assert fake_sub is None, "Label boundary violation: notmalicious-c2.net should NOT match malicious-c2.net!"
print("  [+] Subdomain fuzzy matching correctly respects DNS label boundaries.", flush=True)

# 4.2 CIDR match
cidr_hit = correlator._cidr_ip_lookup("203.0.113.45")
assert cidr_hit is not None and cidr_hit.value == "203.0.113.0/24"
print("  [+] CIDR subnet matching successfully identified 203.0.113.45 inside 203.0.113.0/24.", flush=True)

# 4.3 Deduplication & Aggregation
test_event_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)
mock_log_event1 = LogEvent(
    id=88881,
    timestamp=test_event_time,
    raw_line="OUTBOUND 192.168.1.10 -> 203.0.113.45:443",
    extracted_artifacts=[{"type": "ipv4", "value": "203.0.113.45"}]
)

alerts_initial = correlator.correlate_event(mock_log_event1)
assert len(alerts_initial) == 1
first_alert = alerts_initial[0]
assert first_alert.hit_count == 1
initial_dedupe_key = first_alert.dedupe_key

mock_log_event2 = LogEvent(
    id=88882,
    timestamp=test_event_time + timedelta(minutes=15),
    raw_line="OUTBOUND 192.168.1.10 -> 203.0.113.45:443 repeat",
    extracted_artifacts=[{"type": "ipv4", "value": "203.0.113.45"}]
)

alerts_second = correlator.correlate_event(mock_log_event2)
assert len(alerts_second) == 0, "Repeated event should be aggregated into existing alert, not produce a new row!"

updated_alert = db.query(Alert).filter(Alert.dedupe_key == initial_dedupe_key).first()
assert updated_alert.hit_count == 2
print(f"  [+] Alert deduplication passed: repeated event aggregated into existing alert (hit_count: {updated_alert.hit_count}).", flush=True)

# Clean up test alert
db.delete(updated_alert)
db.commit()

# -------------------------------------------------------------
# 5. INTEGRATION TESTING: STIX 2.1 EXPORT & IMPORT
# -------------------------------------------------------------
print("\n[TEST 5] Testing STIX 2.1 Export & Import...", flush=True)

sample_iocs = db.query(IOC).filter(IOC.is_active == True).limit(5).all()
stix_bundle = export_to_stix21(sample_iocs)
assert stix_bundle["type"] == "bundle"
assert stix_bundle["spec_version"] == "2.1"
assert len(stix_bundle["objects"]) == len(sample_iocs)
print(f"  [+] STIX 2.1 Export verified: valid bundle with {len(stix_bundle['objects'])} indicators.", flush=True)

test_stix_bundle = {
    "type": "bundle",
    "id": "bundle--test-1234",
    "spec_version": "2.1",
    "objects": [
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--test-1",
            "name": "Test Malicious IP",
            "pattern": "[ipv4-addr:value = '198.51.100.88']",
            "pattern_type": "stix",
            "confidence": 88,
            "labels": ["botnet", "c2"]
        }
    ]
}

import_stats = import_stix21_bundle(test_stix_bundle, db)
assert import_stats["new_indicators"] >= 1 or import_stats["updated_indicators"] >= 1
imported_ioc = db.query(IOC).filter(IOC.value == "198.51.100.88").first()
assert imported_ioc is not None
print(f"  [+] STIX 2.1 Import verified: successfully imported {imported_ioc.value} ({imported_ioc.type}).", flush=True)

# -------------------------------------------------------------
# 6. INTEGRATION TESTING: INCIDENT CASE WORKFLOW
# -------------------------------------------------------------
print("\n[TEST 6] Testing Incident Case Lifecycle...", flush=True)

inc = Incident(
    title="Automated Test Campaign Incident",
    description="Test incident for verifying multi-alert association",
    severity="high",
    status="open"
)
db.add(inc)
db.commit()
db.refresh(inc)

assert inc.id is not None
print(f"  [+] Incident created: #{inc.id} - {inc.title}", flush=True)

alert_for_case = db.query(Alert).first()
if alert_for_case:
    alert_for_case.incident_id = inc.id
    db.commit()
    assert alert_for_case.incident.id == inc.id
    print(f"  [+] Linked Alert #{alert_for_case.id} to Incident #{inc.id}.", flush=True)

inc.status = "contained"
inc.resolution_summary = "Containment rules reviewed and verified."
db.commit()
assert inc.status == "contained"
print(f"  [+] Incident updated to status '{inc.status}'.", flush=True)

# -------------------------------------------------------------
# 7. PERFORMANCE BENCHMARKING
# -------------------------------------------------------------
print("\n[TEST 7] Running Performance Benchmarking...", flush=True)

active_iocs_count = len(correlator.exact_matches)
test_queries = [{"type": "ipv4", "value": "185.220.101.5"}] * 100

t0 = time.perf_counter()
for _ in range(50):
    correlator.check_artifacts(test_queries)
elapsed = time.perf_counter() - t0
rate = (50 * 100) / elapsed
latency_us = (elapsed / (50 * 100)) * 1_000_000

print(f"  [+] Correlation Throughput: {rate:,.0f} queries/sec across {active_iocs_count:,} IOCs.", flush=True)
print(f"  [+] Exact Match Latency:    {latency_us:.2f} microseconds per check.", flush=True)

# Clean up test records
db.delete(inc)
if imported_ioc:
    db.delete(imported_ioc)
db.commit()
db.close()
test_engine.dispose()
try:
    if os.path.exists(TEST_COMP_DB): os.remove(TEST_COMP_DB)
    if os.path.exists(TEST_COMP_DB + "-shm"): os.remove(TEST_COMP_DB + "-shm")
    if os.path.exists(TEST_COMP_DB + "-wal"): os.remove(TEST_COMP_DB + "-wal")
except Exception:
    pass

print("\n" + "=" * 70, flush=True)
print("  ALL TESTS PASSED! SENTINEL PLATFORM VALIDATED SUCCESSFULLY.", flush=True)
print("=" * 70, flush=True)
