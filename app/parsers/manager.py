import re
import json
from datetime import datetime
from typing import List, Dict, Any, Iterator, Optional
from app.normalizer import detect_and_normalize

# Optimized regex patterns for network artifact extraction
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
IPV6_REGEX = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
URL_REGEX = re.compile(r'(?:https?|ftp)://[^\s"\'<>\]\[)(\{\}]+')
DOMAIN_REGEX = re.compile(r'\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,5}[a-zA-Z]{2,6}\b')
EMAIL_REGEX = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
SHA1_REGEX   = re.compile(r'\b[a-fA-F0-9]{40}\b')
MD5_REGEX    = re.compile(r'\b[a-fA-F0-9]{32}\b')

# Firewall key-value extractors (e.g. iptables, pfSense, Cisco ASA)
FW_SRC_REGEX = re.compile(r'\b(?:SRC|src|source|srcip|saddr)=([^\s,;]+)', re.IGNORECASE)
FW_DST_REGEX = re.compile(r'\b(?:DST|dst|destination|dstip|daddr)=([^\s,;]+)', re.IGNORECASE)

def parse_log_timestamp(line: str) -> Optional[datetime]:
    """Extracts and parses timestamps from standard Syslog, ISO 8601, and Common Log formats."""
    # 1. ISO 8601 (e.g. 2026-10-30T10:00:00 or 2026-10-30 10:00:00)
    iso_match = re.search(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', line)
    if iso_match:
        try:
            return datetime.fromisoformat(iso_match.group(1).replace(" ", "T"))
        except ValueError:
            pass

    # 2. Apache / Nginx Common Log Format (e.g. 30/Oct/2026:10:00:00)
    clf_match = re.search(r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})', line)
    if clf_match:
        try:
            return datetime.strptime(clf_match.group(1), "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            pass

    # 3. Traditional Syslog (e.g. Oct 30 10:00:00)
    syslog_match = re.search(r'\b([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b', line)
    if syslog_match:
        try:
            current_year = datetime.now().year
            return datetime.strptime(f"{current_year} {syslog_match.group(1)}", "%Y %b %d %H:%M:%S")
        except ValueError:
            pass

    return None

def extract_artifacts_from_line(line: str) -> List[Dict[str, str]]:
    """
    Extracts and normalizes all network and host artifacts from a raw log event.
    Supports structured JSON (Suricata/Zeek), key-value firewall logs, web logs, and Syslog.
    """
    artifacts = []
    seen = set()
    
    def _add(raw: Any):
        if not raw:
            return
        # During log parsing, keep internal endpoint IPs so they are captured in log artifacts
        ioc_type, norm_val = detect_and_normalize(str(raw), is_feed_ioc=False)
        if ioc_type and norm_val and (ioc_type, norm_val) not in seen:
            seen.add((ioc_type, norm_val))
            artifacts.append({"type": ioc_type, "value": norm_val})

    clean_line = line.strip()

    # 1. Structured JSON (Suricata EVE, Zeek, AWS GuardDuty)
    if clean_line.startswith("{") and clean_line.endswith("}"):
        try:
            doc = json.loads(clean_line)
            # Traverse common network and identity fields
            for key in ["src_ip", "dest_ip", "client_ip", "server_ip", "ip", "src", "dst", "id.orig_h", "id.resp_h"]:
                if key in doc: _add(doc[key])
            for key in ["hostname", "domain", "query", "rrname", "host"]:
                if key in doc: _add(doc[key])
            for key in ["url", "uri", "http_uri", "request_uri"]:
                if key in doc: _add(doc[key])
            for key in ["hash", "sha256", "md5", "sha1", "file_hash"]:
                if key in doc: _add(doc[key])
            for key in ["email", "sender", "recipient", "from", "to"]:
                if key in doc: _add(doc[key])
        except Exception:
            pass

    # 2. Key-Value Firewall Patterns (SRC=... DST=...)
    for m in FW_SRC_REGEX.findall(clean_line): _add(m)
    for m in FW_DST_REGEX.findall(clean_line): _add(m)

    # 3. High-Fidelity URLs
    for match in URL_REGEX.findall(clean_line): _add(match)

    # 4. IP Addresses (IPv4 and IPv6)
    for match in IPV4_REGEX.findall(clean_line): _add(match)
    for match in IPV6_REGEX.findall(clean_line): _add(match)

    # 5. Hashes
    for match in SHA256_REGEX.findall(clean_line): _add(match)
    for match in SHA1_REGEX.findall(clean_line): _add(match)
    for match in MD5_REGEX.findall(clean_line): _add(match)

    # 6. Emails
    for match in EMAIL_REGEX.findall(clean_line): _add(match)
    
    # 7. Domains (Strip URLs first to avoid duplicate fragments)
    line_no_urls = URL_REGEX.sub("", clean_line)
    for match in DOMAIN_REGEX.findall(line_no_urls): _add(match)

    return artifacts

def process_log_file(file_path: str, log_type: str = "generic") -> Iterator[Dict[str, Any]]:
    """
    Streams a log file line by line and yields log events with extracted artifacts.
    Memory-efficient streaming generator that never loads the whole file into RAM.
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            
            try:
                artifacts = extract_artifacts_from_line(stripped)
                timestamp = parse_log_timestamp(stripped)
                
                yield {
                    "raw_line": stripped,
                    "timestamp": timestamp,
                    "artifacts": artifacts
                }
            except Exception:
                # Never crash the file streaming on malformed individual lines
                continue
