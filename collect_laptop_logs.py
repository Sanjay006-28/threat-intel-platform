"""
collect_laptop_logs.py
Takes a live snapshot of real outbound network connections and DNS cache
from this Windows laptop and writes them to auto_ingest/laptop_live.log
so the SENTINEL Threat Intel Platform can scan your laptop's live traffic!
"""

import os
import subprocess
import re
from datetime import datetime

def collect_laptop_traffic(output_dir="auto_ingest"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_lines = []

    print("[*] Collecting live network connections from your Windows laptop...")

    # 1. Collect Active TCP/UDP Connections using netstat
    try:
        proc = subprocess.run(["netstat", "-n"], capture_output=True, text=True, timeout=10)
        lines = proc.stdout.splitlines()
        
        for line in lines:
            line = line.strip()
            # Match standard netstat: TCP 192.168.1.10:52311 142.250.182.14:443 ESTABLISHED
            parts = re.split(r'\s+', line)
            if len(parts) >= 4 and parts[0].upper() in ["TCP", "UDP"]:
                proto = parts[0].upper()
                local_addr = parts[1]
                remote_addr = parts[2]
                state = parts[3] if len(parts) > 3 else "CONNECTED"
                
                # Filter out local loopback (127.0.0.1 or 0.0.0.0)
                if not remote_addr.startswith("127.0.0.1") and not remote_addr.startswith("0.0.0.0") and not remote_addr.startswith("[::"):
                    remote_ip = remote_addr.split(":")[0]
                    log_entry = f"{timestamp_str} INFO OUTBOUND {proto} {local_addr} -> {remote_addr} [{state}]"
                    log_lines.append(log_entry)
    except Exception as e:
        print(f"[!] Error collecting netstat: {e}")

    # 2. Collect DNS Cache (recently visited websites)
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "Get-DnsClientCache | Select-Object -ExpandProperty Entry -First 25"],
            capture_output=True, text=True, timeout=10
        )
        dns_entries = [d.strip() for d in proc.stdout.splitlines() if d.strip()]
        for domain in dns_entries:
            if "." in domain and not domain.endswith(".local") and not domain.endswith(".arpa"):
                log_entry = f"{timestamp_str} INFO DNS_QUERY {domain} [CacheLookup]"
                log_lines.append(log_entry)
    except Exception as e:
        print(f"[!] Error collecting DNS cache: {e}")

    if not log_lines:
        log_lines.append(f"{timestamp_str} INFO Laptop idle, no external connections active.")

    # Write to auto_ingest directory
    out_file = os.path.join(output_dir, f"laptop_live_{int(datetime.now().timestamp())}.log")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n")

    print(f"[+] Successfully captured {len(log_lines)} real events from your laptop!")
    print(f"[+] Saved to: {out_file}")
    print("[+] The Sentinel Directory Watcher will automatically ingest and correlate it now.")

if __name__ == "__main__":
    collect_laptop_traffic()
