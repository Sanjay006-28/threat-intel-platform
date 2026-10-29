"""
correlator.py
Correlation Engine — matches extracted IOC entities against the threat DB.

Matching strategies (in order):
  1. Exact match         – direct dict lookup (O(1))
  2. URL-host extraction – checks if the *domain* of a URL is a known IOC
  3. Fuzzy domain match  – checks if an extracted domain ends with a known
                           malicious domain (catches subdomains)
  4. Hash normalization  – case-insensitive hash lookup

MITRE ATT&CK technique mapping included for enrichment.
"""

import re
from urllib.parse import urlparse
from typing import List, Dict, Any

from database import get_connection, save_alert
from log_parser import parse_log_line

# ── MITRE ATT&CK Technique Mapping ───────────────────────────────────────────
ATTACK_MAP: Dict[str, Dict[str, str]] = {
    "c2":               {"id": "T1071", "name": "Application Layer Protocol"},
    "botnet_c2":        {"id": "T1071", "name": "Application Layer Protocol"},
    "botnet":           {"id": "T1498", "name": "Network Denial of Service"},
    "phishing":         {"id": "T1566", "name": "Phishing"},
    "payload_delivery": {"id": "T1105", "name": "Ingress Tool Transfer"},
    "malware":          {"id": "T1204", "name": "User Execution"},
    "ransomware":       {"id": "T1486", "name": "Data Encrypted for Impact"},
    "credential_theft": {"id": "T1110", "name": "Brute Force"},
    "spam":             {"id": "T1598", "name": "Phishing for Information"},
    "exploit":          {"id": "T1203", "name": "Exploitation for Client Execution"},
}

def _get_attack(threat_type: str) -> tuple:
    """Returns (technique_id, technique_name) for a given threat_type."""
    entry = ATTACK_MAP.get(threat_type.lower().strip(), {})
    return entry.get("id", ""), entry.get("name", "")


# ── Correlation Engine ────────────────────────────────────────────────────────

class CorrelationEngine:
    """
    Loads all IOCs into memory on startup for sub-millisecond lookups.
    Call reload_cache() after syncing new threat feeds.
    """

    def __init__(self):
        # Primary cache: {ioc_value (lowercased) -> ioc_record dict}
        self.ioc_cache: Dict[str, Dict[str, Any]] = {}
        # Secondary: set of known malicious domain suffixes (for fuzzy matching)
        self.known_domains: set = set()
        self.reload_cache()

    # ── Cache management ──────────────────────────────────────────────────────

    def reload_cache(self):
        """Loads / refreshes the in-memory IOC lookup tables from SQLite."""
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM iocs")
        rows = cursor.fetchall()
        conn.close()

        self.ioc_cache = {row["ioc_value"].lower(): dict(row) for row in rows}
        # Build domain set for fuzzy suffix matching
        self.known_domains = {
            v for v, r in self.ioc_cache.items()
            if r.get("ioc_type") in ("domain", "url")
        }

    # ── Lookup helpers ────────────────────────────────────────────────────────

    def _exact_lookup(self, value: str) -> Dict[str, Any] | None:
        """Direct O(1) hash-map lookup."""
        return self.ioc_cache.get(value.lower())

    def _domain_from_url(self, url: str) -> str:
        """Extracts hostname from a URL string."""
        try:
            return urlparse(url).hostname or ""
        except Exception:
            return ""

    def _fuzzy_domain_lookup(self, domain: str) -> Dict[str, Any] | None:
        """
        Checks if `domain` is a subdomain of any known malicious domain.
        e.g. 'login.evil.top' will match IOC 'evil.top'
        """
        domain = domain.lower()
        parts = domain.split(".")
        # Check progressively shorter suffixes: a.b.c → b.c → c
        for i in range(1, len(parts)):
            candidate = ".".join(parts[i:])
            if candidate in self.ioc_cache:
                return self.ioc_cache[candidate]
        return None

    def _check_entity(self, entity: Dict[str, str]) -> Dict[str, Any] | None:
        """
        Returns an IOC record if the entity matches any known IOC, else None.
        Applies: exact → URL-host → fuzzy domain matching.
        """
        val  = entity["value"].lower()
        etype = entity["type"]

        # 1. Exact match
        hit = self._exact_lookup(val)
        if hit:
            return hit

        # 2. For URL entities — also look up the bare hostname
        if etype == "url":
            host = self._domain_from_url(val)
            if host:
                hit = self._exact_lookup(host)
                if hit:
                    return hit
                # Fuzzy match on the URL host
                hit = self._fuzzy_domain_lookup(host)
                if hit:
                    return hit

        # 3. Fuzzy suffix match for domain entities
        if etype == "domain":
            hit = self._fuzzy_domain_lookup(val)
            if hit:
                return hit

        return None

    # ── Main correlation method ───────────────────────────────────────────────

    def correlate_log_text(
        self,
        log_text: str,
        log_source: str = "Upload"
    ) -> List[Dict[str, Any]]:
        """
        Processes raw log text line-by-line.

        Returns a list of alert dicts for all IOC matches found.
        Also persists each unique alert to the database.
        """
        alerts_found: List[Dict[str, Any]] = []
        lines = log_text.splitlines()

        for line in lines:
            if not line.strip():
                continue

            entities = parse_log_line(line)
            line_hits: set = set()   # avoid multiple alerts from one line for the same IOC

            for entity in entities:
                threat = self._check_entity(entity)
                if not threat:
                    continue

                ioc_key = threat["ioc_value"].lower()
                if ioc_key in line_hits:
                    continue          # already alerted for this IOC on this line
                line_hits.add(ioc_key)

                technique_id, technique_name = _get_attack(threat.get("threat_type", ""))

                alert = {
                    "matched_ioc":      threat["ioc_value"],
                    "ioc_type":         threat["ioc_type"],
                    "threat_type":      threat.get("threat_type", "unknown"),
                    "malware_family":   threat.get("malware_family", "Unknown"),
                    "severity":         threat.get("severity", "medium"),
                    "confidence_score": threat.get("confidence_score", 75),
                    "log_source":       log_source,
                    "raw_log_line":     line.strip(),
                    "attack_technique": technique_id,
                    "attack_name":      technique_name,
                }

                # Persist (deduplication handled by UNIQUE constraint in DB)
                save_alert(alert)
                alerts_found.append(alert)

        return alerts_found

    # ── Stats ─────────────────────────────────────────────────────────────────
    @property
    def cache_size(self) -> int:
        return len(self.ioc_cache)