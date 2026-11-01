import re
import json
import hashlib
import ipaddress
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Set, Tuple, Optional
from sqlalchemy.orm import Session

from app.models import IOC, Alert, LogEvent, Whitelist
from app.scoring import calculate_score, get_severity
from app.config import settings

logger = logging.getLogger(__name__)

def extract_endpoint_identity(event: LogEvent, matched_ioc_val: str) -> str:
    """
    Extracts the source endpoint or host identifier from a log event.
    Differentiates source IPs so that distinct endpoints triggering hits against
    the same indicator generate separate alerts rather than being merged.
    """
    raw = event.raw_line or ""
    
    # 1. Key-value firewall patterns (SRC=... or source=...)
    fw_match = re.search(r'\b(?:SRC|src|source|srcip|saddr|client_ip)=([^\s,;]+)', raw, re.IGNORECASE)
    if fw_match:
        val = fw_match.group(1).strip().strip('"\'')
        if val != matched_ioc_val:
            return val

    # 2. Structured JSON
    if raw.startswith("{") and raw.endswith("}"):
        try:
            doc = json.loads(raw)
            for k in ["src_ip", "client_ip", "src", "id.orig_h", "source_ip", "host", "computer_name"]:
                val = str(doc.get(k, "")).strip()
                if val and val != matched_ioc_val:
                    return val
        except Exception:
            pass

    # 3. Connection flow syntax: "192.168.1.50:52311 -> 185.220.101.5:443" or "FROM 192.168.1.77" or "at 192.168.1.50"
    flow_match = re.search(r'\b((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?\s*(?:->|-->|to)\s*', raw)
    if flow_match:
        val = flow_match.group(1)
        if val != matched_ioc_val:
            return val

    from_match = re.search(r'\b(?:FROM|from|at|client)\s+((?:\d{1,3}\.){3}\d{1,3})', raw)
    if from_match:
        val = from_match.group(1)
        if val != matched_ioc_val:
            return val

    # 4. Check extracted artifacts for private RFC1918 / loopback IP or any IP != matched_ioc_val
    if event.extracted_artifacts:
        candidates = []
        for art in event.extracted_artifacts:
            val = art.get("value", "")
            typ = art.get("type", "")
            if typ in ["ipv4", "ipv6", "ip"] and val != matched_ioc_val:
                try:
                    ip_obj = ipaddress.ip_address(val)
                    if ip_obj.is_private:
                        return val  # Prioritize private internal host
                    candidates.append(val)
                except ValueError:
                    pass
        if candidates:
            return candidates[0]

    # 5. Regex search for any private RFC1918 IPv4 in the raw line
    all_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw)
    for candidate_ip in all_ips:
        if candidate_ip != matched_ioc_val:
            try:
                if ipaddress.ip_address(candidate_ip).is_private:
                    return candidate_ip
            except ValueError:
                pass

    # 6. Check for user / host identifier in log
    user_match = re.search(r'\b(?:user|username|account):\s*([a-zA-Z0-9_\-\.\$]+)', raw, re.IGNORECASE)
    if user_match:
        return f"User: {user_match.group(1)}"

    host_match = re.search(r'\b(?:Host|hostname):\s*([a-zA-Z0-9_\-\.]+)', raw, re.IGNORECASE)
    if host_match and host_match.group(1) != matched_ioc_val:
        return f"Host: {host_match.group(1)}"

    return "Internal Network (Edge/Proxy)"

class Correlator:
    def __init__(self, db: Session):
        self.db = db
        # Load active IOCs into memory for O(1) matching
        self.active_iocs = self.db.query(IOC).filter(IOC.is_active == True).all()
        
        # Load only active, non-deleted, non-expired whitelist policies
        now = datetime.now(timezone.utc)
        self.whitelist_exact: Dict[str, Whitelist] = {}
        self.whitelist_domains: Dict[str, Whitelist] = {}
        self.whitelist_cidrs: List[Tuple[Any, Whitelist]] = []
        self.whitelist_urls: Dict[str, Whitelist] = {}
        self.whitelist_hashes: Dict[str, Whitelist] = {}
        self._pending_alerts: Dict[str, Alert] = {}

        active_policies = self.db.query(Whitelist).filter(
            Whitelist.is_active == True,
            Whitelist.is_deleted == False
        ).all()

        for w in active_policies:
            if w.expires_at:
                exp = w.expires_at.replace(tzinfo=timezone.utc) if w.expires_at.tzinfo is None else w.expires_at
                if exp <= now:
                    continue  # Expired policy ceases to suppress

            val = (w.value or "").strip()
            if not val:
                continue

            typ = (w.type or "").lower().strip()
            self.whitelist_exact[val] = w

            if typ == "domain":
                self.whitelist_domains[val.lower()] = w
            elif typ == "url" or "://" in val:
                u_clean = val.lower().strip()
                self.whitelist_urls[u_clean] = w
                self.whitelist_urls[u_clean.rstrip("/")] = w
                self.whitelist_urls[u_clean.rstrip("/") + "/"] = w
            elif typ == "ipv6" or (":" in val and "/" not in val and "://" not in val):
                try:
                    ip_v6 = ipaddress.IPv6Address(val)
                    self.whitelist_exact[str(ip_v6)] = w
                    self.whitelist_exact[ip_v6.exploded] = w
                    self.whitelist_exact[ip_v6.compressed] = w
                except ValueError:
                    pass
            elif typ in ["ipv4", "cidr"] or ("/" in val and "://" not in val and ("." in val or ":" in val)):
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    self.whitelist_cidrs.append((net, w))
                except ValueError:
                    pass
            elif typ in ["md5", "sha1", "sha256", "hash"] or len(val) in [32, 40, 64]:
                self.whitelist_hashes[val.lower()] = w

        self.exact_matches: Dict[str, IOC] = {}
        self.domains: Set[str] = set()
        self.cidr_networks: List[Tuple[Any, IOC]] = []
        
        for ioc in self.active_iocs:
            self.exact_matches[ioc.value] = ioc

            # URL trailing slash tolerance: index both with and without trailing slash
            if ioc.type == "url" or "://" in ioc.value:
                u_val = ioc.value.strip()
                self.exact_matches[u_val.rstrip("/")] = ioc
                self.exact_matches[u_val.rstrip("/") + "/"] = ioc

            if ioc.type == "domain":
                self.domains.add(ioc.value.lower())
            
            # Index CIDR blocks (e.g. 194.26.29.0/24)
            if "/" in ioc.value and ("ip" in ioc.type or ioc.type == "cidr"):
                try:
                    net = ipaddress.ip_network(ioc.value.strip(), strict=False)
                    self.cidr_networks.append((net, ioc))
                except ValueError:
                    pass

    def get_matching_whitelist_policy(self, value: str, ioc_type: str = "") -> Optional[Whitelist]:
        """
        Returns the active Whitelist policy covering the given indicator if suppressed,
        or None if not suppressed.
        """
        if not value:
            return None
            
        clean_val = value.strip()
        lower_val = clean_val.lower()
        typ = (ioc_type or "").lower().strip()

        # 1. Exact match (including IPv6 canonical / exploded / compressed)
        if clean_val in self.whitelist_exact:
            return self.whitelist_exact[clean_val]
        if lower_val in self.whitelist_exact:
            return self.whitelist_exact[lower_val]

        if typ == "ipv6" or (":" in clean_val and "/" not in clean_val):
            try:
                ip_v6_in = ipaddress.IPv6Address(clean_val)
                if str(ip_v6_in) in self.whitelist_exact:
                    return self.whitelist_exact[str(ip_v6_in)]
                if ip_v6_in.exploded in self.whitelist_exact:
                    return self.whitelist_exact[ip_v6_in.exploded]
                if ip_v6_in.compressed in self.whitelist_exact:
                    return self.whitelist_exact[ip_v6_in.compressed]
            except ValueError:
                pass

        # 2. Hash match
        if lower_val in self.whitelist_hashes:
            return self.whitelist_hashes[lower_val]

        # 3. URL match (exact match and path-prefix matching)
        if lower_val in self.whitelist_urls:
            return self.whitelist_urls[lower_val]

        if typ == "url" or clean_val.startswith(("http://", "https://")):
            # Check path-prefix matching against configured URL policies
            for wl_url, pol in self.whitelist_urls.items():
                if lower_val == wl_url:
                    return pol
                # Match subpaths or query strings: e.g. https://corp.net/health matches https://corp.net/health?check=1 or https://corp.net/health/v1
                if lower_val.startswith(wl_url.rstrip("/") + "/") or lower_val.startswith(wl_url + "?") or lower_val.startswith(wl_url + "#"):
                    return pol

        # 4. Domain matching respecting DNS label boundaries
        typ = (ioc_type or "").lower().strip()
        if typ == "domain" or ("." in clean_val and "/" not in clean_val and ":" not in clean_val):
            parts = lower_val.split(".")
            for i in range(len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in self.whitelist_domains:
                    return self.whitelist_domains[parent]

        # 5. IP inside whitelisted CIDR range
        if typ in ["ipv4", "ipv6", "ip"] or ("." in clean_val or ":" in clean_val):
            try:
                ip_obj = ipaddress.ip_address(clean_val)
                for net, pol in self.whitelist_cidrs:
                    if ip_obj in net:
                        return pol
            except ValueError:
                pass

        # 6. URL host against domain & CIDR whitelist
        if typ == "url" or clean_val.startswith(("http://", "https://")):
            try:
                import urllib.parse
                parsed = urllib.parse.urlparse(clean_val)
                host = (parsed.hostname or "").lower()
                if host:
                    if host in self.whitelist_domains:
                        return self.whitelist_domains[host]
                    parts = host.split(".")
                    for i in range(len(parts) - 1):
                        parent = ".".join(parts[i:])
                        if parent in self.whitelist_domains:
                            return self.whitelist_domains[parent]
                    try:
                        ip_obj = ipaddress.ip_address(host)
                        for net, pol in self.whitelist_cidrs:
                            if ip_obj in net:
                                return pol
                    except ValueError:
                        pass
            except Exception:
                pass

        return None

    def is_whitelisted(self, value: str, ioc_type: str = "") -> bool:
        """Checks if an indicator or domain/IP is covered by an active whitelist rule."""
        return self.get_matching_whitelist_policy(value, ioc_type) is not None

    def _fuzzy_domain_lookup(self, domain: str) -> Optional[IOC]:
        """
        Finds parent domain if subdomain is queried (e.g. sub.evil.com -> evil.com).
        Strictly respects DNS label boundaries to avoid false matches (e.g. notevil.com != evil.com).
        """
        parts = domain.lower().split(".")
        # Check proper parent domain suffixes
        for i in range(1, len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self.domains:
                return self.exact_matches.get(candidate)
        return None

    def _cidr_ip_lookup(self, ip_str: str) -> Optional[IOC]:
        """Checks if a log IP address falls inside any malicious CIDR subnet block."""
        if not self.cidr_networks:
            return None
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net, ioc in self.cidr_networks:
                if ip_obj in net:
                    return ioc
        except ValueError:
            pass
        return None

    def check_artifacts(self, artifacts: List[Dict[str, str]]) -> List[IOC]:
        """
        Matches extracted log artifacts against active threat intelligence.
        Suppresses any hits that match active whitelist rules.
        """
        matched_iocs = []
        seen_ioc_ids = set()

        for artifact in artifacts:
            val = artifact["value"]
            typ = artifact["type"]
            
            # Check Whitelist suppression first
            matched_policy = self.get_matching_whitelist_policy(val, typ)
            if matched_policy:
                try:
                    from app.audit import log_audit
                    log_audit(
                        self.db,
                        "system",
                        "alert_suppressed",
                        f"Suppressed {typ} [{val}] matching policy #{matched_policy.id} ({matched_policy.type}: {matched_policy.value}). Reason: {matched_policy.reason}"
                    )
                except Exception as e:
                    logger.debug(f"Audit log record error: {e}")
                continue

            matched = None

            # 1. Exact Match (O(1))
            if val in self.exact_matches:
                matched = self.exact_matches[val]
            
            # 2. Fuzzy match for domains / subdomains (respecting DNS label boundaries)
            elif typ == "domain":
                matched = self._fuzzy_domain_lookup(val)

            # 3. CIDR / Subnet match for IP addresses
            elif typ in ["ipv4", "ipv6", "ip"]:
                matched = self._cidr_ip_lookup(val)
                
            if matched and matched.id not in seen_ioc_ids:
                seen_ioc_ids.add(matched.id)
                matched_iocs.append(matched)
                    
        return matched_iocs

    def correlate_event(self, event: LogEvent) -> List[Alert]:
        """
        Correlates a log event with active IOCs.
        Implements time-window alert deduplication and occurrence aggregation.
        """
        if not event.extracted_artifacts:
            return []
            
        iocs = self.check_artifacts(event.extracted_artifacts)
        if not iocs:
            return []

        event_time = event.timestamp if event.timestamp else datetime.now(timezone.utc)
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)

        # Configurable aggregation time-window (e.g., 60 minutes)
        window_seconds = max(300, settings.DEDUPLICATION_WINDOW_MINUTES * 60)
        time_bucket = int(event_time.timestamp() // window_seconds)

        new_alerts = []
        
        for ioc in iocs:
            endpoint = extract_endpoint_identity(event, ioc.value)
            # Deterministic aggregation key per IOC, endpoint and time bucket
            dedupe_str = f"ioc-{ioc.id}-ep-{endpoint}-bucket-{time_bucket}"
            dedupe_key = hashlib.md5(dedupe_str.encode()).hexdigest()
            
            # Count independent sources (deduplicating duplicate feed rows)
            independent_sources = len(set(s.feed_name for s in ioc.sources)) if ioc.sources else 1
            
            # Check if an aggregated alert already exists within this time-window
            existing = self.db.query(Alert).filter(Alert.dedupe_key == dedupe_key).first()
            
            if existing:
                # Update existing alert occurrence count and last_seen timestamp
                existing.hit_count = (existing.hit_count or 1) + 1
                existing.last_seen = event_time
                
                # Recalculate score with updated occurrence frequency
                new_score = calculate_score(
                    ioc_confidence=ioc.confidence,
                    source_count=independent_sources,
                    ioc_type=ioc.type,
                    hit_count=existing.hit_count
                )
                existing.score = new_score
                existing.severity = get_severity(new_score)
                self.db.add(existing)
                continue
            
            # Otherwise create a new aggregated alert
            initial_score = calculate_score(
                ioc_confidence=ioc.confidence,
                source_count=independent_sources,
                ioc_type=ioc.type,
                hit_count=1
            )
            severity = get_severity(initial_score)
            
            alert = Alert(
                ioc_id=ioc.id,
                log_event_id=event.id,
                matched_value=ioc.value,
                matched_type=ioc.type,
                severity=severity,
                score=initial_score,
                status="new",
                hit_count=1,
                first_seen=event_time,
                last_seen=event_time,
                dedupe_key=dedupe_key
            )
            self.db.add(alert)
            new_alerts.append(alert)
            
        if new_alerts:
            self.db.commit()
            for alert in new_alerts:
                self.db.refresh(alert)
                if alert.severity in ["critical", "high"]:
                    try:
                        from app.notifications import send_alert_webhook
                        send_alert_webhook(
                            alert_id=alert.id,
                            matched_value=alert.matched_value,
                            matched_type=alert.matched_type,
                            severity=alert.severity,
                            score=alert.score
                        )
                    except Exception as e:
                        logger.debug(f"Webhook dispatch notification skipped: {e}")
        else:
            self.db.commit()
                
        return new_alerts
