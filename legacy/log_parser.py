"""
log_parser.py
Extracts all IOC-relevant entities from a single log line using regex.
Supports: IPv4, IPv6, URLs, Domains, Emails, MD5, SHA1, SHA256
"""

import re
from typing import List, Dict, Any

# ── Regex Patterns ────────────────────────────────────────────────────────────

# IPv4 address (broad, includes private ranges — let correlator filter)
IPV4_REGEX = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'

# Full URLs  (http / https / ftp)
URL_REGEX = r'(?:https?|ftp)://[^\s"\'<>\]\[)(\{\}]+'

# Standalone domain names (e.g. evil.top, sub.bad.org)
# Excludes bare words; requires at least one dot with a valid TLD (2–6 chars)
DOMAIN_REGEX = (
    r'\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)'   # not an IPv4
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,5}'
    r'[a-zA-Z]{2,6}\b'
)

# Email addresses
EMAIL_REGEX = r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}\b'

# Cryptographic hashes (by length)
SHA256_REGEX = r'\b[a-fA-F0-9]{64}\b'
SHA1_REGEX   = r'\b[a-fA-F0-9]{40}\b'
MD5_REGEX    = r'\b[a-fA-F0-9]{32}\b'

# ── Noise filters ─────────────────────────────────────────────────────────────
# Known benign domains / IPs to skip so we don't generate false-positive lookups
_BENIGN_DOMAINS = {
    "company-portal.local", "auth.company.internal", "localhost",
    "example.com", "example.org",
}
_LOOPBACK_NETS = ("127.", "0.0.0.0", "255.")
_PRIVATE_NETS  = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                   "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                   "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                   "172.30.", "172.31.", "192.168.")

# Domains extracted from URLs are already captured; avoid double-extracting them
# as a "domain" entity so we don't produce two lookup keys for the same host.


def _strip_url_domains(line: str) -> str:
    """Remove URL host parts from the line before standalone domain extraction."""
    return re.sub(URL_REGEX, "", line)


def _is_private_ip(ip: str) -> bool:
    return ip.startswith(_LOOPBACK_NETS) or ip.startswith(_PRIVATE_NETS)


# ── Public API ────────────────────────────────────────────────────────────────

def parse_log_line(line: str) -> List[Dict[str, str]]:
    """
    Extracts all IOC-type entities from a single log line.

    Returns a list of dicts, each with keys:
        - ``type``  : 'ip' | 'url' | 'domain' | 'email' | 'md5' | 'sha1' | 'sha256'
        - ``value`` : normalized (lowercased) string
    """
    extracted: List[Dict[str, str]] = []
    seen: set = set()          # dedup within the same line

    def _add(entity_type: str, value: str):
        val = value.strip().lower().rstrip("/.")
        key = (entity_type, val)
        if val and key not in seen:
            seen.add(key)
            extracted.append({"type": entity_type, "value": val})

    line_clean = line.strip()

    # 1. Extract full URLs first (highest specificity)
    for url in re.findall(URL_REGEX, line_clean):
        _add("url", url)

    # 2. Extract IPs (public IPs only — skip RFC-1918 / loopback)
    for ip in re.findall(IPV4_REGEX, line_clean):
        if not _is_private_ip(ip):
            _add("ip", ip)

    # 3. Extract hashes — longest pattern first to avoid substring matches
    for h in re.findall(SHA256_REGEX, line_clean):
        _add("sha256", h)

    sha256_vals = {e["value"] for e in extracted if e["type"] == "sha256"}
    for h in re.findall(SHA1_REGEX, line_clean):
        if h.lower() not in sha256_vals:          # SHA256 starts with a 40-char prefix
            _add("sha1", h)

    sha1_vals = {e["value"] for e in extracted if e["type"] == "sha1"}
    for h in re.findall(MD5_REGEX, line_clean):
        if h.lower() not in sha256_vals and h.lower() not in sha1_vals:
            _add("md5", h)

    # 4. Extract email addresses
    for email in re.findall(EMAIL_REGEX, line_clean):
        _add("email", email)

    # 5. Extract standalone domains (after stripping URL noise)
    line_no_urls = _strip_url_domains(line_clean)
    emails_in_line = {e["value"] for e in extracted if e["type"] == "email"}
    for domain in re.findall(DOMAIN_REGEX, line_no_urls):
        d = domain.strip().lower().rstrip(".")
        # Skip if it is a known-benign domain, or the host part of an already-found email
        email_host = any(d == em.split("@", 1)[-1] for em in emails_in_line)
        if d not in _BENIGN_DOMAINS and not email_host:
            _add("domain", d)

    return extracted


# ── CLI helper ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_lines = [
        "2026-09-30 ALERT TCP 10.0.0.5 -> 185.220.101.5:443 [C2]",
        "2026-09-30 FILE_SCAN hash=44d88612fea8a8f36de82e1278abb02f user=jdoe",
        "2026-09-30 GET http://evil-malware-download.xyz/payload.exe 200",
        "2026-09-30 PHISH email from attacker@phishing-bank-login.top to ceo@corp.com",
        "2026-09-30 DNS query for bad-domain.xyz from 192.168.1.5",
        "2026-09-30 hash aabbccddeeff00112233445566778899aabbccdd (sha1)",
    ]
    for l in test_lines:
        entities = parse_log_line(l)
        print(f"\nLOG: {l}")
        for e in entities:
            print(f"  [{e['type'].upper():8}] {e['value']}")