import re
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session

from app.models import IOC, IOCSource
from app.normalizer import detect_and_normalize
from app.config import settings

logger = logging.getLogger(__name__)

def generate_stix_pattern(ioc_type: str, ioc_value: str) -> str:
    """Generates standard STIX 2.1 indicator comparison patterns."""
    clean_val = ioc_value.replace("'", "\\'")
    if ioc_type in ["ipv4", "ip"]:
        return f"[ipv4-addr:value = '{clean_val}']"
    elif ioc_type == "ipv6":
        return f"[ipv6-addr:value = '{clean_val}']"
    elif ioc_type == "cidr":
        return f"[network-traffic:dst_ref.value = '{clean_val}']"
    elif ioc_type == "domain":
        return f"[domain-name:value = '{clean_val}']"
    elif ioc_type == "url":
        return f"[url:value = '{clean_val}']"
    elif ioc_type in ["md5", "sha1", "sha256"]:
        return f"[file:hashes.'{ioc_type.upper()}' = '{clean_val}']"
    elif ioc_type == "email":
        return f"[email-addr:value = '{clean_val}']"
    return f"[custom-object:value = '{clean_val}']"

def parse_stix_pattern(pattern: str) -> Tuple[str, str]:
    """Extracts raw indicator value and normalized type from standard STIX 2.1 pattern expressions."""
    if not pattern:
        return None, None
        
    match = re.search(r"=\s*'([^']+)'", pattern)
    if match:
        val = match.group(1).replace("\\'", "'")
        norm_type, norm_val = detect_and_normalize(val, is_feed_ioc=False)
        return norm_type, norm_val
        
    return None, None

def export_to_stix21(iocs: List[IOC]) -> Dict[str, Any]:
    """
    Serializes IOC database records into an OASIS STIX 2.1 compliant JSON bundle.
    """
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    bundle_id = f"bundle--{uuid.uuid4()}"

    stix_objects = []
    for ioc in iocs:
        indicator_id = f"indicator--{uuid.uuid4()}"
        pattern = generate_stix_pattern(ioc.type, ioc.value)
        
        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": ioc.first_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z") if ioc.first_seen else now_iso,
            "modified": ioc.last_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z") if ioc.last_seen else now_iso,
            "name": f"Threat Indicator: {ioc.value}",
            "description": ioc.description or f"SENTINEL Threat Intel: {ioc.type} indicator",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": now_iso,
            "confidence": ioc.confidence or 75,
            "labels": ioc.tags if ioc.tags else [ioc.type, "malware"]
        }
        stix_objects.append(indicator_obj)

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": stix_objects
    }
    return bundle

def import_stix21_bundle(bundle_data: Dict[str, Any], db: Session) -> Dict[str, Any]:
    """
    Imports and normalizes indicators from an OASIS STIX 2.1 or STIX 2.0 JSON bundle.
    """
    if not isinstance(bundle_data, dict) or bundle_data.get("type") != "bundle":
        raise ValueError("Invalid STIX JSON payload: root must be a 'bundle' object.")

    raw_objects = bundle_data.get("objects")
    if not isinstance(raw_objects, list):
        raise ValueError("Invalid STIX JSON payload: 'objects' property must be a list.")

    objects = raw_objects
    new_count = 0
    updated_count = 0
    skipped_count = 0

    ttl_delta = timedelta(days=settings.IOC_TTL_DAYS)

    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            skipped_count += 1
            continue
            continue

        pattern = obj.get("pattern", "")
        norm_type, norm_val = parse_stix_pattern(pattern)
        
        if not norm_val:
            # Fallback to name or description if pattern was not recognized
            name = obj.get("name", "")
            norm_type, norm_val = detect_and_normalize(name, is_feed_ioc=False)

        if not norm_type or not norm_val:
            skipped_count += 1
            continue

        conf = obj.get("confidence", 70)
        desc = obj.get("description") or obj.get("name") or "Imported from STIX 2.1 Bundle"
        tags = obj.get("labels", ["stix-import"])

        ioc = db.query(IOC).filter(IOC.value == norm_val).first()
        now = datetime.now(timezone.utc)
        
        if not ioc:
            ioc = IOC(
                type=norm_type,
                value=norm_val,
                confidence=conf,
                severity="high" if conf >= 75 else "medium",
                tags=tags,
                description=desc,
                first_seen=now,
                last_seen=now,
                expires_at=now + ttl_delta,
                is_active=True
            )
            db.add(ioc)
            db.flush()
            new_count += 1
        else:
            ioc.last_seen = now
            ioc.expires_at = now + ttl_delta
            ioc.is_active = True
            ioc.confidence = max(ioc.confidence, conf)
            updated_count += 1

        source = db.query(IOCSource).filter(IOCSource.ioc_id == ioc.id, IOCSource.feed_name == "STIX 2.1 Bundle").first()
        if not source:
            source = IOCSource(ioc_id=ioc.id, feed_name="STIX 2.1 Bundle", seen_at=now)
            db.add(source)

    db.commit()
    return {
        "new_indicators": new_count,
        "updated_indicators": updated_count,
        "skipped_objects": skipped_count
    }
