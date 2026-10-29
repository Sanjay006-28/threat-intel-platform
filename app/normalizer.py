import re
import ipaddress
from typing import Optional, Tuple
from urllib.parse import urlparse, urlunparse

def refang(value: str) -> str:
    """Refang common defanged IOC formats."""
    value = value.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    value = value.replace("[at]", "@").replace("(at)", "@")
    if value.lower().startswith("hxxp"):
        value = "http" + value[4:]
    return value

def detect_and_normalize(value: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Detects the IOC type and normalizes the value.
    Returns (type, normalized_value) or (None, None) if invalid.
    """
    value = value.strip().strip(".,:;'\"/\\")
    value = refang(value)
    
    # 1. IP Address
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return None, None # Skip private/loopback
        return f"ipv{ip.version}", str(ip)
    except ValueError:
        pass

    lower_val = value.lower()

    # 2. Hashes
    if re.fullmatch(r"[a-f0-9]{32}", lower_val):
        return "md5", lower_val
    if re.fullmatch(r"[a-f0-9]{40}", lower_val):
        return "sha1", lower_val
    if re.fullmatch(r"[a-f0-9]{64}", lower_val):
        return "sha256", lower_val

    # 3. Email
    email_match = re.fullmatch(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$", lower_val)
    if email_match:
        return "email", lower_val

    # 4. URL
    if re.match(r"^https?://", lower_val):
        try:
            parsed = urlparse(value)
            if not parsed.netloc:
                return None, None
            # Normalize: scheme and netloc lowercase, keep path as is
            normalized_url = urlunparse((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            return "url", normalized_url
        except Exception:
            pass

    # 5. Domain
    # Must contain at least one dot, not start/end with dot or hyphen, valid TLD
    domain_match = re.fullmatch(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", lower_val)
    if domain_match:
        return "domain", lower_val

    return None, None
