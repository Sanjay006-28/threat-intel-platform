import re
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any
from app.models import IOC
from app.normalizer import detect_and_normalize

def generate_stix_pattern(ioc_type: str, ioc_value: str) -> str:
    """Generates standard STIX 2.1 indicator patterns."""
    clean_val = ioc_value.replace("'", "\\'")
    if ioc_type in ["ipv4", "ip"]:
        return f"[ipv4-addr:value = '{clean_val}']"
    elif ioc_type == "ipv6":
        return f"[ipv6-addr:value = '{clean_val}']"
    elif ioc_type == "domain":
        return f"[domain-name:value = '{clean_val}']"
    elif ioc_type == "url":
        return f"[url:value = '{clean_val}']"
    elif ioc_type in ["md5", "sha1", "sha256"]:
        return f"[file:hashes.'{ioc_type.upper()}' = '{clean_val}']"
    elif ioc_type == "email":
        return f"[email-addr:value = '{clean_val}']"
    return f"[custom-object:value = '{clean_val}']"

def export_to_stix21(iocs: List[IOC]) -> Dict[str, Any]:
    """
    Serializes a list of IOC database records into an OASIS STIX 2.1 compliant JSON bundle.
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
            "description": ioc.description or f"Identified malicious {ioc.type} indicator",
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

def parse_stix_pattern(pattern: str) -> tuple:
    """Extracts raw value and type from standard STIX 2.1 patterns."""
    match = re.search(r"=\s*'([^']+)'", pattern)
    if match:
        val = match.group(1)
        norm_type, norm_val = detect_and_normalize(val)
        return norm_type, norm_val
    return None, None
