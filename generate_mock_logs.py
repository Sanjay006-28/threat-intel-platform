"""
generate_mock_logs.py
Generates a realistic demo security log file with:
  - clean/benign log lines
  - malicious IOC hits (IPs, URLs, hashes, domains, emails)
"""

from datetime import datetime, timedelta
import random

def generate_sample_log_file(filename: str = "demo_security.log"):
    base_time = datetime(2026, 9, 30, 10, 0, 0)
    
    def ts(offset_secs: int) -> str:
        return (base_time + timedelta(seconds=offset_secs)).strftime("%Y-%m-%d %H:%M:%S")

    logs = [
        # Benign traffic
        f"{ts(0)}    INFO  ACCEPT TCP 192.168.1.105:49152 -> 8.8.8.8:53 [DNS Query: google.com]",
        f"{ts(91)}   INFO  GET /index.html HTTP/1.1 200 Host: company-portal.local User-Agent: Mozilla/5.0",
        f"{ts(180)}  INFO  ACCEPT TCP 192.168.1.120:55432 -> 1.1.1.1:53 [DNS Query: microsoft.com]",
        f"{ts(360)}  INFO  POST /api/login HTTP/1.1 200 Host: auth.company.internal user=alice",

        # ── MALICIOUS IOC HITS ───────────────────────────────────────────
        # Known C2 IP
        f"{ts(502)}  ALERT OUTBOUND TCP 192.168.1.50:52311 -> 185.220.101.5:443 [Suspicious C2 Connection]",

        # Known malware URL
        f"{ts(765)}  WARN  GET /payload.exe HTTP/1.1 200 Host: evil-malware-download.xyz URL: http://evil-malware-download.xyz/payload.exe",

        # Subdomain of malicious domain (fuzzy match test)
        f"{ts(920)}  WARN  DNS QUERY login.phishing-bank-login.top FROM 192.168.1.77",

        # Known MD5 hash (EICAR test file)
        f"{ts(1032)} WARN  FILE_SCAN Executable downloaded hash=44d88612fea8a8f36de82e1278abb02f by user: jdoe at 192.168.1.50",

        # Known SHA256 hash
        f"{ts(1140)} ALERT FILE_EXEC process=svchost.exe sha256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",

        # Phishing email IOC
        f"{ts(1300)} WARN  EMAIL_RECEIVED from=attacker@phishing-bank-login.top to=ceo@corp.com subject='Urgent: Account Verification'",

        # Known botnet IP
        f"{ts(1450)} ALERT OUTBOUND UDP 192.168.1.88:5353 -> 194.26.29.112:53 [Botnet C2 Beacon]",

        # AsyncRAT C2
        f"{ts(1560)} ALERT TCP 10.0.0.15 -> 91.92.251.103:8808 [AsyncRAT C2 detected by EDR]",

        # More benign
        f"{ts(1800)} INFO  ACCEPT TCP 192.168.1.200:60001 -> 142.250.182.14:443 [HTTPS: gmail.com]",
        f"{ts(2100)} INFO  GET /api/status HTTP/1.1 200 Host: company-portal.local",
    ]

    with open(filename, "w") as f:
        f.write("\n".join(logs))

    malicious_count = 8
    print(f"[+] Created {filename} with {len(logs)} log lines ({malicious_count} malicious IOC hits).")
    return filename


if __name__ == "__main__":
    generate_sample_log_file()