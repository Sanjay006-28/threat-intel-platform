import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any

# Illegal characters for command strings to prevent shell / PowerShell injection
DANGEROUS_CHARS_REGEX = re.compile(r"[\s;`$|&><\"'\n\r\t\(\)\{\}\[\]\\]")

def is_safe_shell_string(s: str) -> bool:
    """Checks if a string is completely free of shell control characters."""
    return not bool(DANGEROUS_CHARS_REGEX.search(s))

def validate_ioc_for_remediation(ioc_type: str, ioc_value: str) -> bool:
    """Validates that the IOC strictly matches expected syntax for its declared type."""
    val = ioc_value.strip()
    if not val:
        return False

    if ioc_type in ["ipv4", "ip"]:
        try:
            ip = ipaddress.IPv4Address(val)
            return not (ip.is_loopback or ip.is_unspecified)
        except ValueError:
            return False

    elif ioc_type == "ipv6":
        try:
            ip = ipaddress.IPv6Address(val)
            return not (ip.is_loopback or ip.is_unspecified)
        except ValueError:
            return False

    elif ioc_type == "cidr":
        try:
            net = ipaddress.ip_network(val, strict=False)
            return not (net.is_loopback or net.is_reserved)
        except ValueError:
            return False

    elif ioc_type == "domain":
        if len(val) > 253 or not is_safe_shell_string(val):
            return False
        return bool(re.fullmatch(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", val))

    elif ioc_type == "url":
        try:
            parsed = urlparse(val)
            if not parsed.scheme or not parsed.netloc:
                return False
            host = parsed.netloc.split(":")[0]
            return is_safe_shell_string(host)
        except Exception:
            return False

    elif ioc_type in ["md5", "sha1", "sha256"]:
        return bool(re.fullmatch(r"^[a-fA-F0-9]{32,64}$", val))

    return False

def generate_remediation_rules(ioc_type: str, ioc_value: str, alert_id: int = 1) -> Dict[str, Any]:
    """
    Generates ready-to-deploy firewall, DNS sinkhole, and IDS rules for an IOC.
    Rules are generated strictly for analyst inspection and copy-paste execution.
    SENTINEL does not automatically apply or execute rules on the system.
    """
    clean_val = ioc_value.strip()
    norm_type = ioc_type.lower()

    rules = {
        "ioc_value": clean_val,
        "ioc_type": norm_type,
        "is_valid": True,
        "validation_error": None,
        "iptables": None,
        "windows_firewall": None,
        "dns_sinkhole": None,
        "suricata_snort": None,
        "proxy_acl": None,
        "safety_notice": "SENTINEL generates containment rules for analyst review and manual execution only. Never execute unverified rules in production."
    }

    # Strict input validation to prevent command injection
    if not validate_ioc_for_remediation(norm_type, clean_val):
        rules["is_valid"] = False
        rules["validation_error"] = f"Value '{clean_val}' failed strict validation for type '{norm_type}'. Remediation generation aborted for safety."
        return rules

    sid_base = 1000000 + (alert_id % 500000)

    # 1. IP & CIDR Remediation Rules
    if norm_type in ["ipv4", "ipv6", "ip", "cidr"]:
        # Safe iptables rules
        rules["iptables"] = (
            f"# Linux iptables: Block inbound and outbound communication with {clean_val}\n"
            f"sudo iptables -A INPUT -s {clean_val} -j DROP\n"
            f"sudo iptables -A OUTPUT -d {clean_val} -j DROP"
        )
        
        # Windows Defender PowerShell with unique rule names
        inbound_name = f"SENTINEL-Block-Inbound-{alert_id}-{clean_val}"
        outbound_name = f"SENTINEL-Block-Outbound-{alert_id}-{clean_val}"
        rules["windows_firewall"] = (
            f"# Windows PowerShell: Block inbound and outbound connections via Defender Firewall\n"
            f'New-NetFirewallRule -DisplayName "{outbound_name}" -Direction Outbound '
            f'-RemoteAddress "{clean_val}" -Action Block -Description "SENTINEL CTI Alert #{alert_id}"\n'
            f'New-NetFirewallRule -DisplayName "{inbound_name}" -Direction Inbound '
            f'-RemoteAddress "{clean_val}" -Action Block -Description "SENTINEL CTI Alert #{alert_id}"'
        )

        # Suricata / Snort IDS Signature
        rules["suricata_snort"] = (
            f'drop ip any any -> {clean_val} any '
            f'(msg:"SENTINEL ALERT - Outbound connection to malicious indicator [{clean_val}]"; '
            f'classtype:trojan-activity; sid:{sid_base}; rev:1;)'
        )

    # 2. Domain & URL Remediation Rules
    elif norm_type in ["domain", "url"]:
        domain = clean_val
        if norm_type == "url":
            parsed = urlparse(clean_val)
            domain = parsed.netloc.split(":")[0] if parsed.netloc else clean_val

        rules["dns_sinkhole"] = (
            f"# Local /etc/hosts or Pi-hole DNS sinkhole entry\n"
            f"0.0.0.0 {domain}\n"
            f"::1 {domain}"
        )
        rules["suricata_snort"] = (
            f'drop dns any any -> any any '
            f'(msg:"SENTINEL ALERT - DNS Query to Malicious Domain [{domain}]"; '
            f'dns.query; content:"{domain}"; nocase; sid:{sid_base + 1000}; rev:1;)'
        )
        rules["proxy_acl"] = (
            f"# Squid Proxy Deny Access Rule\n"
            f"acl sentinel_blocked_dst dstdomain .{domain}\n"
            f"http_access deny sentinel_blocked_dst"
        )

    # 3. Cryptographic Hash Rules
    elif norm_type in ["md5", "sha1", "sha256"]:
        rules["suricata_snort"] = (
            f'alert http any any -> any any '
            f'(msg:"SENTINEL ALERT - Download of Malicious File Hash [{clean_val}]"; '
            f'file.hash:{norm_type}; content:"{clean_val.lower()}"; sid:{sid_base + 2000}; rev:1;)'
        )
        rules["windows_firewall"] = (
            f"# Microsoft Defender Threat & Vulnerability Indicator Note:\n"
            f"# Add SHA256/MD5 hash '{clean_val.lower()}' to Microsoft Defender for Endpoint blocklist.\n"
            f"# PowerShell Defender Exclusion Check:\n"
            f"# Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"
        )

    return rules
