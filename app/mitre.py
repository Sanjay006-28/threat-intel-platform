import re
from typing import List, Dict, Any, Optional

# Knowledge base mapping threat tags and keywords to MITRE ATT&CK Techniques
MITRE_TACTIC_MAP = {
    "c2": {
        "tactic": "Command and Control",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "description": "Adversaries communicate using OSI application layer protocols to avoid detection.",
        "url": "https://attack.mitre.org/techniques/T1071/"
    },
    "botnet": {
        "tactic": "Command and Control",
        "technique_id": "T1584",
        "technique_name": "Compromise Infrastructure",
        "description": "Adversaries compromise 3rd-party systems to establish botnet command channels.",
        "url": "https://attack.mitre.org/techniques/T1584/"
    },
    "rat": {
        "tactic": "Command and Control",
        "technique_id": "T1219",
        "technique_name": "Remote Access Software",
        "description": "Adversaries abuse legitimate or custom remote access tools for command and interactive control.",
        "url": "https://attack.mitre.org/techniques/T1219/"
    },
    "phishing": {
        "tactic": "Initial Access",
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "description": "Adversaries send phishing messages to gain access to victim systems or credentials.",
        "url": "https://attack.mitre.org/techniques/T1566/"
    },
    "ransomware": {
        "tactic": "Impact",
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "description": "Adversaries encrypt data on target systems to interrupt availability and extort ransom.",
        "url": "https://attack.mitre.org/techniques/T1486/"
    },
    "stealer": {
        "tactic": "Credential Access",
        "technique_id": "T1555",
        "technique_name": "Credentials from Password Stores",
        "description": "Adversaries search common password storage locations to harvest credentials.",
        "url": "https://attack.mitre.org/techniques/T1555/"
    },
    "loader": {
        "tactic": "Execution",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "description": "Adversaries transfer tools or payloads from external infrastructure into the network.",
        "url": "https://attack.mitre.org/techniques/T1105/"
    },
    "payload": {
        "tactic": "Execution",
        "technique_id": "T1204",
        "technique_name": "User Execution: Malicious File",
        "description": "An adversary relies on user action to gain execution of malicious code.",
        "url": "https://attack.mitre.org/techniques/T1204/"
    },
    "trojan": {
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "description": "Adversaries abuse command interpreters to execute arbitrary commands or trojaned scripts.",
        "url": "https://attack.mitre.org/techniques/T1059/"
    },
    "ddos": {
        "tactic": "Impact",
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "description": "Adversaries degrade network service availability through volumetric traffic flood.",
        "url": "https://attack.mitre.org/techniques/T1498/"
    },
    "dns": {
        "tactic": "Command and Control",
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "description": "Adversaries communicate using the Domain Name System (DNS) protocol for C2 or exfiltration.",
        "url": "https://attack.mitre.org/techniques/T1071/004/"
    }
}

# Signatures for direct log-line evidence
LOG_EVIDENCE_SIGNATURES = [
    (r"\bDNS\s+QUERY\b", "dns", "Active DNS protocol query to malicious domain recorded in telemetry"),
    (r"\bFILE_EXEC\b|\bprocess=\b", "payload", "Process execution / suspicious binary launch recorded by host agent"),
    (r"\bAsyncRAT\b|\bEDR\b", "rat", "EDR endpoint detection matched Remote Access Trojan activity"),
    (r"\bEMAIL_RECEIVED\b|\bfrom=.*@.*\b", "phishing", "Inbound email transmission telemetry matched spearphishing artifacts"),
    (r"\bOUTBOUND\b.*(?:C2|Beacon)", "c2", "Outbound command-and-control connection observed by network edge"),
]

def get_mitre_mapping(
    tags: Optional[List[str]] = None, 
    description: str = "", 
    ioc_type: str = "", 
    raw_log: str = ""
) -> List[Dict[str, Any]]:
    """
    Extracts relevant MITRE ATT&CK techniques with rigorous provenance attribution:
    1. DIRECT: Identified from explicit security log events (DNS query, process exec, EDR).
    2. INTEL_CONTEXT: Corroborated by threat intelligence tags or feed descriptions.
    3. HEURISTIC: Inferred strictly from indicator type syntax (not definitive host evidence).
    """
    matches = []
    seen_ids = set()

    # 1. Direct Log Evidence Extraction (Highest Provenance)
    if raw_log:
        for pattern, key, rationale in LOG_EVIDENCE_SIGNATURES:
            if re.search(pattern, raw_log, re.IGNORECASE):
                mitre = MITRE_TACTIC_MAP.get(key)
                if mitre and mitre["technique_id"] not in seen_ids:
                    seen_ids.add(mitre["technique_id"])
                    item = dict(mitre)
                    item["confidence"] = "Direct (Log Evidence)"
                    item["mapping_type"] = "DIRECT"
                    item["rationale"] = rationale
                    matches.append(item)

    # 2. Contextual Threat Intelligence Tag & Description Mapping
    corpus_words = set()
    if tags:
        for t in tags:
            if t:
                tokens = re.findall(r"[a-zA-Z0-9]+", str(t).lower())
                corpus_words.update(tokens)
    if description:
        tokens = re.findall(r"[a-zA-Z0-9]+", str(description).lower())
        corpus_words.update(tokens)

    for key, mitre in MITRE_TACTIC_MAP.items():
        if key in corpus_words and mitre["technique_id"] not in seen_ids:
            seen_ids.add(mitre["technique_id"])
            item = dict(mitre)
            item["confidence"] = "High (Tag Evidence)"
            item["mapping_type"] = "INTEL_CONTEXT"
            item["rationale"] = f"Corroborated by threat feed tag/description keyword '{key}'"
            matches.append(item)

    # 3. Heuristic Fallback (Clearly labeled as Type-Based Presumption)
    if not matches:
        ioc_norm = (ioc_type or "").lower()
        if ioc_norm in ["url", "domain"]:
            item = dict(MITRE_TACTIC_MAP["c2"])
            item["confidence"] = "Category Heuristic"
            item["mapping_type"] = "HEURISTIC"
            item["rationale"] = f"Heuristic association inferred from {ioc_norm.upper()} indicator syntax. Not definitive proof of adversary activity on this host."
            matches.append(item)
        elif ioc_norm in ["md5", "sha1", "sha256"]:
            item = dict(MITRE_TACTIC_MAP["payload"])
            item["confidence"] = "Category Heuristic"
            item["mapping_type"] = "HEURISTIC"
            item["rationale"] = f"Heuristic association inferred from file hash syntax ({ioc_norm.upper()}). Requires host execution confirmation."
            matches.append(item)
        elif ioc_norm in ["ipv4", "ipv6", "ip", "cidr"]:
            item = dict(MITRE_TACTIC_MAP["c2"])
            item["confidence"] = "Category Heuristic"
            item["mapping_type"] = "HEURISTIC"
            item["rationale"] = f"Heuristic association inferred from IP routing address ({ioc_norm.upper()}). May represent shared hosting or proxy infrastructure."
            matches.append(item)
        elif ioc_norm == "email":
            item = dict(MITRE_TACTIC_MAP["phishing"])
            item["confidence"] = "Category Heuristic"
            item["mapping_type"] = "HEURISTIC"
            item["rationale"] = "Heuristic association inferred from email address syntax."
            matches.append(item)

    return matches
