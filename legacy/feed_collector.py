"""
feed_collector.py
Collects IOCs from multiple free threat-intelligence sources:
  • ThreatFox         – malware C2 / payload IPs, domains, URLs, hashes
  • URLhaus            – malware distribution URLs
  • MalwareBazaar      – malicious file hashes (MD5 / SHA1 / SHA256)
  • Feodo Tracker      – botnet C2 IP blocklist
  • PhishTank          – phishing URLs  (requires free API key)
  • Sample fallback    – 10 hardcoded IOCs for offline demo / testing
"""

import requests
from datetime import datetime
from typing import Dict, List
from database import insert_ioc, init_db

# ── Timeouts & limits ─────────────────────────────────────────────────────────
REQUEST_TIMEOUT = 15   # seconds
MAX_IOCS_PER_FEED = 200

# ── Offline fallback IOCs (always loaded for demo) ────────────────────────────
SAMPLE_IOCS: List[Dict] = [
    # IPs
    {"ioc_value": "185.220.101.5",   "ioc_type": "ip",     "threat_type": "c2",               "malware_family": "Cobalt Strike",  "confidence_score": 95, "severity": "critical", "source": "SampleFeed"},
    {"ioc_value": "194.26.29.112",   "ioc_type": "ip",     "threat_type": "botnet",            "malware_family": "Mirai",          "confidence_score": 85, "severity": "high",     "source": "SampleFeed"},
    {"ioc_value": "91.92.251.103",   "ioc_type": "ip",     "threat_type": "c2",               "malware_family": "AsyncRAT",       "confidence_score": 90, "severity": "critical", "source": "SampleFeed"},
    # Domains
    {"ioc_value": "phishing-bank-login.top", "ioc_type": "domain", "threat_type": "phishing", "malware_family": "Generic Phish",  "confidence_score": 80, "severity": "high",     "source": "SampleFeed"},
    {"ioc_value": "evil-malware-download.xyz","ioc_type": "domain","threat_type": "payload_delivery","malware_family": "RedLine", "confidence_score": 90, "severity": "critical", "source": "SampleFeed"},
    {"ioc_value": "update-windows-defender.com","ioc_type":"domain","threat_type":"phishing",  "malware_family": "FakeSoftware",   "confidence_score": 85, "severity": "high",     "source": "SampleFeed"},
    # URLs
    {"ioc_value": "http://evil-malware-download.xyz/payload.exe", "ioc_type": "url", "threat_type": "payload_delivery", "malware_family": "RedLine", "confidence_score": 90, "severity": "critical", "source": "SampleFeed"},
    # Hashes
    {"ioc_value": "44d88612fea8a8f36de82e1278abb02f", "ioc_type": "md5",    "threat_type": "malware", "malware_family": "EICAR Test",  "confidence_score": 100, "severity": "low",  "source": "SampleFeed"},
    {"ioc_value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "ioc_type": "sha256", "threat_type": "malware", "malware_family": "EICAR Test", "confidence_score": 100, "severity": "low", "source": "SampleFeed"},
    # Email
    {"ioc_value": "attacker@phishing-bank-login.top", "ioc_type": "email", "threat_type": "phishing", "malware_family": "SpearPhish", "confidence_score": 80, "severity": "high", "source": "SampleFeed"},
]

# ── Severity helper ──────────────────────────────────────────────────────────
def _score_to_severity(score: int) -> str:
    if score >= 90:  return "critical"
    if score >= 75:  return "high"
    if score >= 50:  return "medium"
    return "low"


# ── Feed 1: ThreatFox (IPs, domains, URLs, hashes) ───────────────────────────
def fetch_threatfox_iocs(limit: int = MAX_IOCS_PER_FEED) -> int:
    """ThreatFox – recent malware C2 indicators from abuse.ch."""
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "get_iocs", "days": 1}
    added = 0
    try:
        resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok":
            return 0
        for item in data.get("data", [])[:limit]:
            raw_type = item.get("ioc_type", "")
            ioc_val  = item.get("ioc", "").strip()
            # Normalize type
            if "ip:port" in raw_type or raw_type == "ip":
                ioc_val   = ioc_val.split(":")[0]
                ioc_type  = "ip"
            elif "domain" in raw_type:
                ioc_type  = "domain"
            elif "url" in raw_type:
                ioc_type  = "url"
            elif "md5_hash"  in raw_type: ioc_type = "md5"
            elif "sha256_hash" in raw_type or len(ioc_val) == 64: ioc_type = "sha256"
            elif "sha1_hash" in raw_type or len(ioc_val) == 40:   ioc_type = "sha1"
            else: ioc_type = "unknown"

            score = item.get("confidence_level", 75)
            record = {
                "ioc_value":        ioc_val.lower(),
                "ioc_type":         ioc_type,
                "threat_type":      item.get("threat_type", "malware"),
                "malware_family":   item.get("malware_printable", "Unknown"),
                "confidence_score": score,
                "severity":         _score_to_severity(score),
                "source":           "ThreatFox",
                "tags":             None,
            }
            if insert_ioc(record):
                added += 1
    except Exception as e:
        print(f"[!] ThreatFox error: {e}")
    return added


# ── Feed 2: URLhaus (malware distribution URLs) ───────────────────────────────
def fetch_urlhaus_iocs(limit: int = MAX_IOCS_PER_FEED) -> int:
    """URLhaus – live malware distribution URLs from abuse.ch."""
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    added = 0
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        items = resp.json().get("urls", [])[:limit]
        for item in items:
            if item.get("url_status", "online") not in ("online", "unknown"):
                continue
            tags = item.get("tags") or []
            family = tags[-1] if tags else "Unknown"
            record = {
                "ioc_value":        item["url"].strip().lower(),
                "ioc_type":         "url",
                "threat_type":      "payload_delivery",
                "malware_family":   family,
                "confidence_score": 85,
                "severity":         "high",
                "source":           "URLhaus",
                "tags":             ",".join(tags) if tags else None,
            }
            if insert_ioc(record):
                added += 1
    except Exception as e:
        print(f"[!] URLhaus error: {e}")
    return added


# ── Feed 3: MalwareBazaar (recent malicious hashes) ──────────────────────────
def fetch_malwarebazaar_hashes(limit: int = MAX_IOCS_PER_FEED) -> int:
    """MalwareBazaar – recent malicious file hashes from abuse.ch."""
    url  = "https://mb-api.abuse.ch/api/v1/"
    body = {"query": "get_recent", "selector": "100"}
    added = 0
    try:
        resp = requests.post(url, data=body, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok":
            return 0
        for item in data.get("data", [])[:limit]:
            sha256 = item.get("sha256_hash", "").strip().lower()
            sha1   = item.get("sha1_hash",   "").strip().lower()
            md5    = item.get("md5_hash",     "").strip().lower()
            family = item.get("signature") or item.get("tags", ["Unknown"])[0] if item.get("tags") else "Unknown"
            base = {
                "threat_type":      "malware",
                "malware_family":   family,
                "confidence_score": 90,
                "severity":         "high",
                "source":           "MalwareBazaar",
                "tags":             ",".join(item.get("tags", [])) or None,
            }
            for val, typ in [(sha256, "sha256"), (sha1, "sha1"), (md5, "md5")]:
                if val:
                    if insert_ioc({**base, "ioc_value": val, "ioc_type": typ}):
                        added += 1
    except Exception as e:
        print(f"[!] MalwareBazaar error: {e}")
    return added


# ── Feed 4: Feodo Tracker (botnet C2 IPs) ────────────────────────────────────
def fetch_feodo_ips(limit: int = MAX_IOCS_PER_FEED) -> int:
    """Feodo Tracker – active botnet C2 IP blocklist from abuse.ch."""
    url  = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    added = 0
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        for item in resp.json()[:limit]:
            record = {
                "ioc_value":        item.get("ip_address", "").strip(),
                "ioc_type":         "ip",
                "threat_type":      "botnet_c2",
                "malware_family":   item.get("malware", "Unknown"),
                "confidence_score": 95,
                "severity":         "critical",
                "source":           "FeodoTracker",
                "tags":             item.get("country"),
            }
            if record["ioc_value"] and insert_ioc(record):
                added += 1
    except Exception as e:
        print(f"[!] FeodoTracker error: {e}")
    return added


# ── Fallback: hardcoded sample IOCs ──────────────────────────────────────────
def load_fallback_iocs() -> int:
    count = 0
    for ioc in SAMPLE_IOCS:
        ioc.setdefault("tags", None)
        if insert_ioc(ioc):
            count += 1
    return count


# ── Master collector ──────────────────────────────────────────────────────────
def run_all_collectors(include_sample: bool = True) -> Dict[str, int]:
    """
    Runs all feed collectors and returns a dict of {feed_name: new_ioc_count}.
    Always loads fallback IOCs for offline demo reliability.
    """
    init_db()
    results = {}

    print("[*] Fetching ThreatFox …")
    results["ThreatFox"]       = fetch_threatfox_iocs()

    print("[*] Fetching URLhaus …")
    results["URLhaus"]          = fetch_urlhaus_iocs()

    print("[*] Fetching MalwareBazaar …")
    results["MalwareBazaar"]    = fetch_malwarebazaar_hashes()

    print("[*] Fetching Feodo Tracker …")
    results["FeodoTracker"]     = fetch_feodo_ips()

    if include_sample:
        results["SampleFeed"]   = load_fallback_iocs()

    total = sum(results.values())
    print(f"[+] Collection complete. New IOCs added: {total}")
    return results


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    res = run_all_collectors()
    for feed, count in res.items():
        print(f"  {feed}: {count} new IOCs")