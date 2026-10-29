import re
import json
from typing import List, Dict, Any, Iterator
from app.normalizer import detect_and_normalize

# Regex patterns for fast extraction before strict validation
IPV4_REGEX = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
URL_REGEX = r'(?:https?|ftp)://[^\s"\'<>\]\[)(\{\}]+'
DOMAIN_REGEX = r'\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,5}[a-zA-Z]{2,6}\b'
EMAIL_REGEX = r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}\b'
SHA256_REGEX = r'\b[a-fA-F0-9]{64}\b'
SHA1_REGEX   = r'\b[a-fA-F0-9]{40}\b'
MD5_REGEX    = r'\b[a-fA-F0-9]{32}\b'

def extract_artifacts_from_line(line: str) -> List[Dict[str, str]]:
    """Generic extraction using regex + normalizer with JSON parser support."""
    artifacts = []
    seen = set()
    
    def _add(raw: str):
        if not raw:
            return
        ioc_type, norm_val = detect_and_normalize(str(raw))
        if ioc_type and norm_val and (ioc_type, norm_val) not in seen:
            seen.add((ioc_type, norm_val))
            artifacts.append({"type": ioc_type, "value": norm_val})

    # Try structured JSON (Suricata EVE, Zeek, AWS GuardDuty)
    if line.startswith("{") and line.endswith("}"):
        try:
            doc = json.loads(line)
            # Traverse common network fields
            for key in ["src_ip", "dest_ip", "client_ip", "server_ip", "ip", "src", "dst"]:
                if key in doc: _add(doc[key])
            for key in ["hostname", "domain", "query", "rrname"]:
                if key in doc: _add(doc[key])
            for key in ["url", "uri", "http_uri"]:
                if key in doc: _add(doc[key])
            for key in ["hash", "sha256", "md5", "sha1"]:
                if key in doc: _add(doc[key])
            for key in ["email", "sender", "recipient"]:
                if key in doc: _add(doc[key])
        except Exception:
            pass

    # Generic regex fallback & supplement
    for match in re.findall(URL_REGEX, line): _add(match)
    for match in re.findall(IPV4_REGEX, line): _add(match)
    for match in re.findall(SHA256_REGEX, line): _add(match)
    for match in re.findall(SHA1_REGEX, line): _add(match)
    for match in re.findall(MD5_REGEX, line): _add(match)
    for match in re.findall(EMAIL_REGEX, line): _add(match)
    
    # Strip URLs to avoid double counting domains
    line_no_urls = re.sub(URL_REGEX, "", line)
    for match in re.findall(DOMAIN_REGEX, line_no_urls): _add(match)

    return artifacts

def process_log_file(file_path: str, log_type: str = "generic") -> Iterator[Dict[str, Any]]:
    """
    Streams a log file line by line and yields log events with extracted artifacts.
    Memory-efficient generator.
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            artifacts = extract_artifacts_from_line(line)
            
            # Timestamp extraction (ISO or Common Log Format)
            ts_match = re.search(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', line)
            timestamp = ts_match.group(0) if ts_match else None
            
            yield {
                "raw_line": line,
                "timestamp": timestamp,
                "artifacts": artifacts
            }
