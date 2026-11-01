import re
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple, Optional
from sqlalchemy.orm import Session

from app.models import IOC, IOCSource
from app.normalizer import detect_and_normalize
from app.config import settings

logger = logging.getLogger(__name__)

# Standard OASIS STIX 2.1 hash mapping: hyphenated uppercase names
STIX_HASH_KEY_MAP = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha512": "SHA-512",
}

def generate_stix_pattern(ioc_type: str, ioc_value: str) -> str:
    """
    Generates standard OASIS STIX 2.1 indicator comparison patterns.
    Uses official STIX 2.1 vocabulary and hyphenated hash keys ('SHA-256', 'SHA-1', 'MD5').
    """
    clean_val = ioc_value.replace("'", "\\'")
    typ = (ioc_type or "").lower().strip()

    if typ in ["ipv4", "ip"]:
        return f"[ipv4-addr:value = '{clean_val}']"
    elif typ == "ipv6":
        return f"[ipv6-addr:value = '{clean_val}']"
    elif typ == "cidr":
        if ":" in clean_val:
            return f"[ipv6-addr:value = '{clean_val}']"
        return f"[ipv4-addr:value = '{clean_val}']"
    elif typ == "domain":
        return f"[domain-name:value = '{clean_val}']"
    elif typ == "url":
        return f"[url:value = '{clean_val}']"
    elif typ in ["md5", "sha1", "sha256", "sha512", "hash"]:
        if typ == "hash":
            if len(clean_val) == 32:
                key = "MD5"
            elif len(clean_val) == 40:
                key = "SHA-1"
            else:
                key = "SHA-256"
        else:
            key = STIX_HASH_KEY_MAP.get(typ, "SHA-256")
        return f"[file:hashes.'{key}' = '{clean_val}']"
    elif typ == "email":
        return f"[email-addr:value = '{clean_val}']"
    return f"[custom-object:value = '{clean_val}']"

def parse_stix_pattern(pattern: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extracts raw indicator value and normalized type from standard STIX 2.1 pattern expressions.
    Handles hyphenated and non-hyphenated hash objects.
    """
    if not pattern:
        return None, None
        
    match = re.search(r"=\s*'([^']+)'", pattern)
    if not match:
        return None, None
        
    val = match.group(1).replace("\\'", "'")
    
    # Try normalizer first
    norm_type, norm_val = detect_and_normalize(val, is_feed_ioc=False)
    
    # If type is ambiguous or undetected, deduce from pattern object type
    if not norm_type:
        pattern_lower = pattern.lower()
        if "file:hashes.'sha-256'" in pattern_lower or "file:hashes.'sha256'" in pattern_lower:
            norm_type = "sha256"
        elif "file:hashes.'sha-1'" in pattern_lower or "file:hashes.'sha1'" in pattern_lower:
            norm_type = "sha1"
        elif "file:hashes.'md5'" in pattern_lower:
            norm_type = "md5"
        elif "domain-name:value" in pattern_lower:
            norm_type = "domain"
        elif "url:value" in pattern_lower:
            norm_type = "url"
        elif "ipv4-addr:value" in pattern_lower:
            norm_type = "ipv4"
        elif "ipv6-addr:value" in pattern_lower:
            norm_type = "ipv6"
        elif "email-addr:value" in pattern_lower:
            norm_type = "email"

    return norm_type, norm_val if norm_val else val

def export_to_stix21(iocs: List[IOC]) -> Dict[str, Any]:
    """
    Serializes IOC database records into an OASIS STIX 2.1 compliant JSON bundle.
    Guarantees no sensitive credentials or internal configuration secrets are exposed.
    """
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    bundle_id = f"bundle--{uuid.uuid4()}"

    stix_objects = []
    for ioc in iocs:
        # Ignore inactive indicators
        if not ioc.is_active:
            continue
            
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

        pattern = obj.get("pattern", "")
        norm_type, norm_val = parse_stix_pattern(pattern)
        
        if not norm_val:
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
