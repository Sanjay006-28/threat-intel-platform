import re
import ipaddress
from typing import Optional, Tuple
from urllib.parse import urlparse, urlunparse

# Common defanged formats
DEFANG_DOT_REGEX = re.compile(r"\[\.\]|\(\.\)|\{\.\}")
DEFANG_AT_REGEX = re.compile(r"\[at\]|\(at\)", re.IGNORECASE)

def refang(value: str) -> str:
    """Refangs common defanged IOC syntax."""
    value = DEFANG_DOT_REGEX.sub(".", value)
    value = DEFANG_AT_REGEX.sub("@", value)
    # Refang hxxp / hxxps
    if value.lower().startswith("hxxps://"):
        value = "https://" + value[8:]
    elif value.lower().startswith("hxxp://"):
        value = "http://" + value[7:]
    elif value.lower().startswith("hxxps"):
        value = "https" + value[5:]
    elif value.lower().startswith("hxxp"):
        value = "http" + value[4:]
    return value.strip()

def detect_and_normalize(value: str, is_feed_ioc: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """
    Detects the IOC type and normalizes the value.
    - If is_feed_ioc=True (threat feed ingestion), private/loopback IPs are rejected.
    - If is_feed_ioc=False (log parsing), private endpoint IPs are kept and normalized as ipv4/ipv6.
    Returns (type, normalized_value) or (None, None) if invalid.
    """
    if not value or not isinstance(value, str):
        return None, None
        
    val = value.strip().strip(".,:;'\"\\")
    val = refang(val)
    if not val:
        return None, None

    # 1. CIDR Network Range Detection (e.g. 194.26.29.0/24 or 2001:db8::/32)
    if "/" in val and not val.startswith("http://") and not val.startswith("https://"):
        try:
            net = ipaddress.ip_network(val, strict=False)
            if is_feed_ioc and (net.is_private or net.is_loopback or net.is_reserved):
                return None, None
            return "cidr", str(net)
        except ValueError:
            pass

    # 2. IP Address (IPv4 / IPv6)
    try:
        ip = ipaddress.ip_address(val)
        if is_feed_ioc and (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_unspecified):
            return None, None
        return f"ipv{ip.version}", str(ip)
    except ValueError:
        pass

    lower_val = val.lower()

    # 3. Cryptographic Hashes (MD5: 32 hex, SHA1: 40 hex, SHA256: 64 hex)
    if re.fullmatch(r"^[a-f0-9]{32}$", lower_val):
        return "md5", lower_val
    if re.fullmatch(r"^[a-f0-9]{40}$", lower_val):
        return "sha1", lower_val
    if re.fullmatch(r"^[a-f0-9]{64}$", lower_val):
        return "sha256", lower_val

    # 4. Email Address
    email_match = re.fullmatch(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$", lower_val)
    if email_match:
        return "email", lower_val

    # 5. URL Normalization
    # Canonicalize scheme and netloc to lowercase, preserve case-sensitive paths & queries
    if lower_val.startswith("http://") or lower_val.startswith("https://"):
        try:
            parsed = urlparse(val)
            if not parsed.netloc:
                return None, None
            
            # Normalize hostname / netloc (lowercase)
            host = parsed.netloc.lower()
            # Canonicalize path (ensure leading slash if netloc is followed by path)
            norm_path = parsed.path if parsed.path else "/"
            
            normalized_url = urlunparse((
                parsed.scheme.lower(),
                host,
                norm_path,
                parsed.params,
                parsed.query,
                "" # Strip fragments for threat indicators
            ))
            return "url", normalized_url
        except Exception:
            pass

    # 6. Domain Name Validation & Normalization
    # Check domain label lengths (1-63 chars per label), allowed characters, and valid TLD (>=2 chars)
    if "." in lower_val and len(lower_val) <= 253:
        domain_pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
        if re.fullmatch(domain_pattern, lower_val):
            return "domain", lower_val

    return None, None
