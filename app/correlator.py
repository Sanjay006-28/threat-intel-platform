import hashlib
import ipaddress
import logging
from typing import List, Dict, Any, Set, Tuple
from sqlalchemy.orm import Session
from app.models import IOC, Alert, LogEvent, Whitelist
from app.scoring import calculate_score, get_severity

logger = logging.getLogger(__name__)

class Correlator:
    def __init__(self, db: Session):
        self.db = db
        # Load active IOCs into memory for O(1) matching
        self.active_iocs = self.db.query(IOC).filter(IOC.is_active == True).all()
        
        # Load whitelist
        whitelisted_values = {w.value for w in self.db.query(Whitelist).all()}
        
        self.exact_matches: Dict[str, IOC] = {}
        self.domains: Set[str] = set()
        self.cidr_networks: List[Tuple[Any, IOC]] = []
        
        for ioc in self.active_iocs:
            if ioc.value in whitelisted_values:
                continue
                
            self.exact_matches[ioc.value] = ioc

            if ioc.type == "domain":
                self.domains.add(ioc.value)
            
            # Check for CIDR block representations (e.g., 194.26.29.0/24)
            if "/" in ioc.value and ("ip" in ioc.type or ioc.type == "cidr"):
                try:
                    net = ipaddress.ip_network(ioc.value.strip(), strict=False)
                    self.cidr_networks.append((net, ioc))
                except ValueError:
                    pass

    def _fuzzy_domain_lookup(self, domain: str) -> IOC:
        """Finds parent domain if subdomain is queried (e.g. sub.evil.com -> evil.com)."""
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self.domains:
                return self.exact_matches.get(candidate)
        return None

    def _cidr_ip_lookup(self, ip_str: str) -> IOC:
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
        matched_iocs = []
        for artifact in artifacts:
            val = artifact["value"]
            typ = artifact["type"]
            
            # 1. Exact Match (O(1))
            if val in self.exact_matches:
                matched_iocs.append(self.exact_matches[val])
                continue
            
            # 2. Fuzzy match for domains / subdomains
            if typ == "domain":
                fuzzy = self._fuzzy_domain_lookup(val)
                if fuzzy:
                    matched_iocs.append(fuzzy)
                    continue

            # 3. CIDR / Subnet match for IP addresses
            if typ in ["ipv4", "ipv6", "ip"]:
                cidr_match = self._cidr_ip_lookup(val)
                if cidr_match:
                    matched_iocs.append(cidr_match)
                    continue
                    
        return matched_iocs

    def correlate_event(self, event: LogEvent) -> List[Alert]:
        if not event.extracted_artifacts:
            return []
            
        iocs = self.check_artifacts(event.extracted_artifacts)
        alerts = []
        
        for ioc in iocs:
            # Generate dedupe key: hash of ioc_id + log_event_id
            dedupe_str = f"{ioc.id}-{event.id}"
            dedupe_key = hashlib.md5(dedupe_str.encode()).hexdigest()
            
            # Check if alert already exists
            existing = self.db.query(Alert).filter(Alert.dedupe_key == dedupe_key).first()
            if existing:
                continue
            
            score = calculate_score(
                ioc_confidence=ioc.confidence,
                source_count=len(ioc.sources) if ioc.sources else 1,
                ioc_type=ioc.type,
                hit_count=1
            )
            severity = get_severity(score)
            
            alert = Alert(
                ioc_id=ioc.id,
                log_event_id=event.id,
                matched_value=ioc.value,
                matched_type=ioc.type,
                severity=severity,
                score=score,
                dedupe_key=dedupe_key
            )
            self.db.add(alert)
            alerts.append(alert)
            
        if alerts:
            self.db.commit()
            for alert in alerts:
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
                        logger.debug(f"Webhook dispatch skipped: {e}")
                
        return alerts
