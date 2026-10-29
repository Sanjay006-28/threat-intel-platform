import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.database import SessionLocal
from app.models import IOC
from app.correlator import Correlator
from app.enrichment import enrich_ioc
from app.mitre import get_mitre_mapping
from app.remediation import generate_remediation_rules
from app.parsers.manager import extract_artifacts_from_line

print("=== TESTING SENTINEL CTI ENHANCEMENTS ===")

db = SessionLocal()

# 1. Test CIDR Matching
print("\n[1] Testing CIDR Subnet Matching...")
correlator = Correlator(db)
# Add a temporary mock CIDR subnet to correlator
import ipaddress
mock_net = ipaddress.ip_network("198.51.100.0/24")
mock_ioc = IOC(value="198.51.100.0/24", type="cidr", confidence=90)
correlator.cidr_networks.append((mock_net, mock_ioc))

matched = correlator.check_artifacts([{"type": "ipv4", "value": "198.51.100.42"}])
assert len(matched) == 1, "CIDR matching failed!"
print(f"  [+] Success: 198.51.100.42 matched CIDR subnet {matched[0].value}")

# 2. Test MITRE ATT&CK Mapping
print("\n[2] Testing MITRE ATT&CK Mapping...")
mitre_res = get_mitre_mapping(tags=["botnet", "c2"], description="Emotet C2 Server", ioc_type="ipv4")
assert len(mitre_res) >= 1, "MITRE mapping failed!"
for m in mitre_res:
    print(f"  [+] Mapped technique: {m['technique_id']} ({m['technique_name']}) under tactic: {m['tactic']}")

# 3. Test Remediation Rule Generator
print("\n[3] Testing Remediation Rule Generator...")
rules_ip = generate_remediation_rules("ipv4", "185.220.101.5", 101)
assert rules_ip["iptables"] is not None
assert rules_ip["windows_firewall"] is not None
assert rules_ip["suricata_snort"] is not None
print("  [+] Generated Linux iptables, Windows Defender Firewall, and Suricata rules successfully.")

rules_domain = generate_remediation_rules("domain", "evil-malware-download.xyz", 102)
assert rules_domain["dns_sinkhole"] is not None
assert rules_domain["proxy_acl"] is not None
print("  [+] Generated DNS sinkhole and Squid proxy ACL rules successfully.")

# 4. Test Structured JSON / Suricata Log Parsing
print("\n[4] Testing Structured JSON Log Extraction...")
json_log = '{"timestamp":"2026-10-24T12:00:00Z", "src_ip":"192.168.1.100", "dest_ip":"185.220.101.5", "proto":"TCP", "hostname":"c2-beacon.ru"}'
artifacts = extract_artifacts_from_line(json_log)
extracted_vals = [a["value"] for a in artifacts]
assert "185.220.101.5" in extracted_vals
assert "c2-beacon.ru" in extracted_vals
print(f"  [+] Structured JSON successfully parsed artifacts: {extracted_vals}")

# 5. Test IOC Enrichment
print("\n[5] Testing IOC Enrichment...")
enrichment = enrich_ioc("ipv4", "8.8.8.8")
print(f"  [+] Enriched 8.8.8.8 -> Country: {enrichment.get('country')}, Org: {enrichment.get('org')}, Reverse DNS: {enrichment.get('reverse_dns')}")

print("\n=== ALL ENHANCEMENT TESTS PASSED PERFECTLY! ===")
