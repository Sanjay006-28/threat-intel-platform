import re
from typing import Dict, Any

def generate_remediation_rules(ioc_type: str, ioc_value: str, alert_id: int = 1) -> Dict[str, Any]:
    """
    Generates ready-to-deploy firewall, DNS sinkhole, and IDS rules for an IOC.
    """
    clean_val = ioc_value.strip()
    rules = {
        "ioc_value": clean_val,
        "ioc_type": ioc_type,
        "iptables": None,
        "windows_firewall": None,
        "dns_sinkhole": None,
        "suricata_snort": None,
        "proxy_acl": None
    }

    sid = 1000000 + alert_id

    if ioc_type in ["ipv4", "ipv6", "ip", "cidr"]:
        rules["iptables"] = (
            f"# Block inbound and outbound traffic to {clean_val}\n"
            f"sudo iptables -A INPUT -s {clean_val} -j DROP\n"
            f"sudo iptables -A OUTPUT -d {clean_val} -j DROP"
        )
        rules["windows_firewall"] = (
            f"# Windows PowerShell Firewall Block Rule\n"
            f'New-NetFirewallRule -DisplayName "TIP-Block-{clean_val}" -Direction Outbound '
            f'-RemoteAddress "{clean_val}" -Action Block\n'
            f'New-NetFirewallRule -DisplayName "TIP-Block-{clean_val}" -Direction Inbound '
            f'-RemoteAddress "{clean_val}" -Action Block'
        )
        rules["suricata_snort"] = (
            f'drop ip any any -> {clean_val} any '
            f'(msg:"TIP ALERT - Outbound connection to malicious IP [{clean_val}]"; '
            f'classtype:trojan-activity; sid:{sid}; rev:1;)'
        )

    elif ioc_type in ["domain", "url"]:
        domain = clean_val
        if ioc_type == "url":
            match = re.search(r'https?://([^/:\s]+)', clean_val)
            domain = match.group(1) if match else clean_val

        rules["dns_sinkhole"] = (
            f"# /etc/hosts or Pi-hole block entry\n"
            f"0.0.0.0 {domain}\n"
            f"::1 {domain}"
        )
        rules["suricata_snort"] = (
            f'drop dns any any -> any any '
            f'(msg:"TIP ALERT - DNS Query to Malicious Domain [{domain}]"; '
            f'dns.query; content:"{domain}"; nocase; sid:{sid}; rev:1;)'
        )
        rules["proxy_acl"] = (
            f"# Squid Proxy Deny ACL\n"
            f"acl tip_blocked_domain dstdomain .{domain}\n"
            f"http_access deny tip_blocked_domain"
        )

    elif ioc_type in ["md5", "sha1", "sha256"]:
        rules["suricata_snort"] = (
            f'alert http any any -> any any '
            f'(msg:"TIP ALERT - Download of Malicious File Hash [{clean_val}]"; '
            f'file.hash:{ioc_type.lower()}; content:"{clean_val}"; sid:{sid}; rev:1;)'
        )
        rules["windows_firewall"] = (
            f"# AppLocker / Defender Hash Exclusion Note\n"
            f"# Add hash {clean_val} to Microsoft Defender Threat & Vulnerability blocklist"
        )

    return rules
