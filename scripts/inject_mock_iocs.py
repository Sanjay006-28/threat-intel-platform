import os
import sys

# Ensure project root is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.database import SessionLocal
from app.models import IOC, IOCSource

def inject_mock_iocs():
    db = SessionLocal()
    
    mock_iocs = [
        {"type": "ipv4", "value": "185.220.101.5", "desc": "Suspicious C2 Connection"},
        {"type": "domain", "value": "evil-malware-download.xyz", "desc": "Known malware URL"},
        {"type": "url", "value": "http://evil-malware-download.xyz/payload.exe", "desc": "Malware download URL"},
        {"type": "domain", "value": "phishing-bank-login.top", "desc": "Phishing domain"},
        {"type": "md5", "value": "44d88612fea8a8f36de82e1278abb02f", "desc": "EICAR test file hash"},
        {"type": "sha256", "value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "desc": "Known malicious hash"},
        {"type": "email", "value": "attacker@phishing-bank-login.top", "desc": "Phishing email"},
        {"type": "ipv4", "value": "194.26.29.112", "desc": "Botnet C2 IP"},
        {"type": "ipv4", "value": "91.92.251.103", "desc": "AsyncRAT C2"}
    ]

    print("[*] Injecting mock IOCs into the database...")
    for item in mock_iocs:
        # Check if exists
        existing = db.query(IOC).filter(IOC.value == item["value"]).first()
        if not existing:
            ioc = IOC(
                type=item["type"],
                value=item["value"],
                confidence=99,
                severity="critical",
                description=item["desc"],
                tags=["mock", "testing"]
            )
            db.add(ioc)
            db.commit()
            db.refresh(ioc)
            
            source = IOCSource(ioc_id=ioc.id, feed_name="SampleFeed", reference_url="local")
            db.add(source)
            db.commit()
            
    db.close()
    print("[+] Mock IOCs successfully injected!")

if __name__ == "__main__":
    inject_mock_iocs()
