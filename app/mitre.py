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

def get_mitre_mapping(tags: Optional[List[str]] = None, description: str = "", ioc_type: str = "") -> List[Dict[str, Any]]:
    """
    Extracts relevant MITRE ATT&CK techniques based on IOC tags, description, and type.
    Uses whole-word boundary matching to avoid false partial word matches.
    """
    matches = []
    seen_ids = set()

    corpus_words = set()
    if tags:
        for t in tags:
            if t:
                # Tokenize into clean lowercase words
                tokens = re.findall(r"[a-zA-Z0-9]+", str(t).lower())
                corpus_words.update(tokens)
    if description:
        tokens = re.findall(r"[a-zA-Z0-9]+", str(description).lower())
        corpus_words.update(tokens)

    # Whole-word tag mapping
    for key, mitre in MITRE_TACTIC_MAP.items():
        if key in corpus_words and mitre["technique_id"] not in seen_ids:
            seen_ids.add(mitre["technique_id"])
            item = dict(mitre)
            item["confidence"] = "High (Tag Evidence)"
            matches.append(item)

    # General category fallback when no specific threat tag matched
    if not matches:
        if ioc_type in ["url", "domain"]:
            item = dict(MITRE_TACTIC_MAP["c2"])
            item["confidence"] = "Category Heuristic"
            matches.append(item)
        elif ioc_type in ["md5", "sha1", "sha256"]:
            item = dict(MITRE_TACTIC_MAP["payload"])
            item["confidence"] = "Category Heuristic"
            matches.append(item)
        elif ioc_type in ["ipv4", "ipv6", "ip", "cidr"]:
            item = dict(MITRE_TACTIC_MAP["c2"])
            item["confidence"] = "Category Heuristic"
            matches.append(item)
        elif ioc_type == "email":
            item = dict(MITRE_TACTIC_MAP["phishing"])
            item["confidence"] = "Category Heuristic"
            matches.append(item)

    return matches
