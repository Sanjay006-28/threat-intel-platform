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

def capture_html(html_content, output_filename, width, height):
    temp_html = os.path.abspath(f"temp_shot_{os.path.basename(output_filename)}.html")
    with open(temp_html, "w", encoding="utf-8") as f:
        f.write(html_content)

    screenshot_path = os.path.abspath(output_filename)
    os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)

    cmd = [
        CHROME_PATH,
        "--headless=new",
        "--disable-gpu",
        "--virtual-time-budget=4000",
        f"--window-size={width},{height}",
        f"--screenshot={screenshot_path}",
        temp_html
    ]
    subprocess.run(cmd, timeout=30, check=True)
    size = os.path.getsize(screenshot_path)
    print(f"[+] Saved {output_filename} ({width}x{height}) - {size:,} bytes")

    if os.path.exists(temp_html):
        os.remove(temp_html)

    # Copy to artifact dir
    artifact_dest = os.path.join(ARTIFACT_DIR, os.path.basename(output_filename))
    shutil.copyfile(screenshot_path, artifact_dest)
    print(f"    -> Mirrored to artifact directory: {artifact_dest}")

def main():
    s = requests.Session()
    # 1. Login to get authenticated session cookie
    r_login = s.post(
        "http://127.0.0.1:8000/login",
        data={"username": settings.ADMIN_USERNAME, "password": settings.ADMIN_PASSWORD},
        allow_redirects=False
    )
    print("Login status:", r_login.status_code)

    # 2. Update Incident #1 to generate fresh flash message and updated state
    update_data = {
        "status": "investigating",
        "severity": "critical",
        "analyst_notes": "Active multi-source investigation: IOC beaconing detected across internal hosts 192.168.1.50 and 192.168.1.88. Correlated with FeodoTracker and URLhaus feeds.",
        "resolution_summary": "Initial containment in progress. Sinkholing C2 domain and monitoring perimeter firewall logs."
    }
    r_update = s.post(
        "http://127.0.0.1:8000/incidents/1/update",
        data=update_data,
        allow_redirects=False
    )
    print("Update status:", r_update.status_code, "Redirect Location:", r_update.headers.get("location"))

    # 3. Fetch Incident Cases Overview with flash message
    r_overview = s.get("http://127.0.0.1:8000/incidents?msg=Incident+%231+updated+successfully.")
    overview_html = r_overview.text
    if "<head>" in overview_html:
        overview_html = overview_html.replace("<head>", '<head><base href="http://127.0.0.1:8000/">')

    # Capture Overview at 1366, 1440, and 1600
    capture_html(overview_html, "docs/screenshots/04_incident_ledger_1366.png", width=1366, height=850)
    capture_html(overview_html, "docs/screenshots/04_incident_ledger_1440.png", width=1440, height=900)
    capture_html(overview_html, "docs/screenshots/04_incident_ledger_1600.png", width=1600, height=950)

    # 4. Fetch Incident Detail page for Incident #1
    r_detail = s.get("http://127.0.0.1:8000/incidents/1")
    detail_html = r_detail.text
    if "<head>" in detail_html:
        detail_html = detail_html.replace("<head>", '<head><base href="http://127.0.0.1:8000/">')

    # Capture Detail at 1366, 1440, and 1600
    capture_html(detail_html, "docs/screenshots/05_incident_detail_1366.png", width=1366, height=900)
    capture_html(detail_html, "docs/screenshots/05_incident_detail_1440.png", width=1440, height=950)
    capture_html(detail_html, "docs/screenshots/05_incident_detail_1600.png", width=1600, height=1000)

    print("\nAll screenshots captured and verified successfully.")

if __name__ == "__main__":
    main()

