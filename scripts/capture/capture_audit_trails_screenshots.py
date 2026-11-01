import requests
import subprocess
import os
import shutil
import sys
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.config import settings

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
ARTIFACT_DIR = r"C:\Users\dsanj\.gemini\antigravity\brain\2b88f966-c292-45b9-854a-7c7cf39167d9"

RESOLUTIONS = [
    (1366, 768, "10_audit_trails_1366.png"),
    (1440, 900, "10_audit_trails_1440.png"),
    (1600, 900, "10_audit_trails_1600.png"),
]

def capture_html(html_content, output_filename, width, height):
    temp_html = os.path.abspath(f"temp_shot_audit_{width}_{height}.html")
    processed_html = html_content.replace('href="/static/', 'href="http://127.0.0.1:8000/static/')
    processed_html = processed_html.replace('src="/static/', 'src="http://127.0.0.1:8000/static/')

    with open(temp_html, "w", encoding="utf-8") as f:
        f.write(processed_html)

    artifact_dest = os.path.join(ARTIFACT_DIR, output_filename)
    os.makedirs(os.path.dirname(artifact_dest), exist_ok=True)

    cmd = [
        CHROME_PATH,
        "--headless=new",
        "--disable-gpu",
        "--virtual-time-budget=3000",
        f"--window-size={width},{height}",
        f"--screenshot={artifact_dest}",
        temp_html
    ]
    subprocess.run(cmd, timeout=30, check=True)
    size = os.path.getsize(artifact_dest)
    print(f"[+] Saved {output_filename} ({width}x{height}) - {size:,} bytes")

    if os.path.exists(temp_html):
        os.remove(temp_html)

def main():
    s = requests.Session()
    # 1. Login
    r_login = s.post(
        "http://127.0.0.1:8000/login",
        data={"username": settings.ADMIN_USERNAME, "password": settings.ADMIN_PASSWORD},
        allow_redirects=True
    )
    print("Login status:", r_login.status_code)

    # 2. Get /audit-logs
    r_audit = s.get("http://127.0.0.1:8000/audit-logs")
    print(f"Audit logs page status: {r_audit.status_code}")
    if r_audit.status_code != 200:
        print("Failed to fetch audit logs page")
        return

    for width, height, filename in RESOLUTIONS:
        capture_html(r_audit.text, filename, width, height)

if __name__ == "__main__":
    main()

