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
    fw_match = re.search(r'\b(?:SRC|src|source|srcip|saddr)=([^\s,;]+)', raw, re.IGNORECASE)
    if fw_match:
        val = fw_match.group(1).strip()
        if val != matched_ioc_val:
            return val

    # 2. Structured JSON
    if raw.startswith("{") and raw.endswith("}"):
        try:
            doc = json.loads(raw)
            for k in ["src_ip", "client_ip", "src", "id.orig_h", "source_ip", "host"]:
                val = str(doc.get(k, "")).strip()
                if val and val != matched_ioc_val:
                    return val
        except Exception:
            pass

    # 3. Check extracted artifacts for private RFC1918 / loopback IP or any IP != matched_ioc_val
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

    return "host-default"

class Correlator:
    def __init__(self, db: Session):
        self.db = db
        # Load active IOCs into memory for O(1) matching
        self.active_iocs = self.db.query(IOC).filter(IOC.is_active == True).all()
        
        # Load whitelist entries with typed structures
        self.whitelist_exact: Set[str] = set()
        self.whitelist_domains: Set[str] = set()
        self.whitelist_cidrs: List[Any] = []
        
        for w in self.db.query(Whitelist).all():
            val = w.value.strip()
            self.whitelist_exact.add(val)
            if w.type == "domain":
                self.whitelist_domains.add(val.lower())
            elif "/" in val and ("ip" in w.type or w.type == "cidr"):
                try:
                    self.whitelist_cidrs.append(ipaddress.ip_network(val, strict=False))
                except ValueError:
                    pass

        self.exact_matches: Dict[str, IOC] = {}
        self.domains: Set[str] = set()
        self.cidr_networks: List[Tuple[Any, IOC]] = []
        
        for ioc in self.active_iocs:
            if self.is_whitelisted(ioc.value, ioc.type):
                continue
                
            self.exact_matches[ioc.value] = ioc

            if ioc.type == "domain":
                self.domains.add(ioc.value.lower())
            
            # Index CIDR blocks (e.g. 194.26.29.0/24)
            if "/" in ioc.value and ("ip" in ioc.type or ioc.type == "cidr"):
                try:
                    net = ipaddress.ip_network(ioc.value.strip(), strict=False)
                    self.cidr_networks.append((net, ioc))
                except ValueError:
                    pass

    def is_whitelisted(self, value: str, ioc_type: str = "") -> bool:
        """Checks if an indicator or domain/IP is covered by an active whitelist rule."""
        if not value:
            return False
            
        clean_val = value.strip()
        if clean_val in self.whitelist_exact:
            return True

        # Check domain label boundaries
        if ioc_type == "domain" or ("." in clean_val and "/" not in clean_val):
            parts = clean_val.lower().split(".")
            for i in range(len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in self.whitelist_domains:
                    return True

        # Check IP inside whitelisted CIDR range
        if ioc_type in ["ipv4", "ipv6", "ip"] or ("." in clean_val or ":" in clean_val):
            try:
                ip_obj = ipaddress.ip_address(clean_val)
                for net in self.whitelist_cidrs:
                    if ip_obj in net:
                        return True
            except ValueError:
                pass

        return False

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
            if self.is_whitelisted(val, typ):
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
