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
    }
}

def get_mitre_mapping(tags: Optional[List[str]] = None, description: str = "", ioc_type: str = "") -> List[Dict[str, str]]:
    """
    Extracts relevant MITRE ATT&CK techniques based on IOC tags, description, and type.
    """
    matches = []
    seen_ids = set()

    search_terms = []
    if tags:
        for t in tags:
            if t:
                search_terms.extend(str(t).lower().replace("-", " ").replace("_", " ").split())
    if description:
        search_terms.extend(str(description).lower().replace("-", " ").replace("_", " ").split())

    for term in search_terms:
        for key, mitre in MITRE_TACTIC_MAP.items():
            if key in term and mitre["technique_id"] not in seen_ids:
                seen_ids.add(mitre["technique_id"])
                matches.append(mitre)

    # Fallback heuristic based on IOC type if no tags matched
    if not matches:
        if ioc_type in ["url", "domain"]:
            matches.append(MITRE_TACTIC_MAP["c2"])
        elif ioc_type in ["md5", "sha1", "sha256"]:
            matches.append(MITRE_TACTIC_MAP["payload"])
        elif ioc_type in ["ipv4", "ipv6", "ip"]:
            matches.append(MITRE_TACTIC_MAP["c2"])
        elif ioc_type == "email":
            matches.append(MITRE_TACTIC_MAP["phishing"])

    return matches
