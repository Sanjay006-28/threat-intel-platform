import os
import shutil
import subprocess
import requests
from PIL import Image

from app.config import settings

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
ARTIFACT_DIR = r"C:\Users\dsanj\.gemini\antigravity\brain\2b88f966-c292-45b9-854a-7c7cf39167d9"

WORKSPACE_FIGURES = r"C:\Users\dsanj\Downloads\threat_intel_platform\figures"
PROJECT_FIGURES = r"C:\Users\dsanj\Downloads\threat_intel_platform\threat_intel_platform\figures"

WIDTH = 1440
HEIGHT = 900

TARGETS = [
    {
        "filename": "02_ingestion_and_correlation.png",
        "url": "http://127.0.0.1:8000/logs",
        "name": "Security Log Ingestion & Stream"
    },
    {
        "filename": "03_dashboard.png",
        "url": "http://127.0.0.1:8000/",
        "name": "SOC Dashboard"
    },
    {
        "filename": "04_security_alerts.png",
        "url": "http://127.0.0.1:8000/alerts",
        "name": "Security Alerts"
    },
    {
        "filename": "05_incident_investigation.png",
        "url": "http://127.0.0.1:8000/incidents/1",
        "name": "Incident Investigation"
    }
]

def capture_page(session, target, dest_dir):
    filename = target["filename"]
    url = target["url"]
    name = target["name"]
    output_path = os.path.join(dest_dir, filename)

    print(f"\n[*] Fetching {name} from {url}...")
    resp = session.get(url)
    assert resp.status_code == 200, f"Failed to fetch {url}, got HTTP {resp.status_code}"

    html = resp.text
    # Ensure static resources point to local server
    html = html.replace('href="/static/', 'href="http://127.0.0.1:8000/static/')
    html = html.replace('src="/static/', 'src="http://127.0.0.1:8000/static/')
    if "<head>" in html:
        html = html.replace("<head>", '<head><base href="http://127.0.0.1:8000/">')

    temp_html = os.path.abspath(f"temp_fig_{filename}.html")
    with open(temp_html, "w", encoding="utf-8") as f:
        f.write(html)

    cmd = [
        CHROME_PATH,
        "--headless=new",
        "--disable-gpu",
        "--virtual-time-budget=4000",
        f"--window-size={WIDTH},{HEIGHT}",
        f"--screenshot={os.path.abspath(output_path)}",
        temp_html
    ]

    print(f"[*] Capturing screenshot via Chrome Headless ({WIDTH}x{HEIGHT})...")
    subprocess.run(cmd, timeout=30, check=True)

    if os.path.exists(temp_html):
        os.remove(temp_html)

    # Validate output image with Pillow
    assert os.path.exists(output_path), f"Output file {output_path} does not exist!"
    file_size = os.path.getsize(output_path)
    with Image.open(output_path) as img:
        img_w, img_h = img.size
        img_format = img.format
        assert img_format == "PNG", f"Expected PNG format, got {img_format}"
        print(f"[+] Successfully captured {filename}:")
        print(f"    - Dimensions: {img_w} x {img_h}")
        print(f"    - File Size: {file_size:,} bytes")
        print(f"    - Format: {img_format}")

    # Mirror to artifact directory
    artifact_path = os.path.join(ARTIFACT_DIR, filename)
    shutil.copyfile(output_path, artifact_path)
    print(f"    -> Mirrored to artifact directory: {artifact_path}")

    return output_path

def main():
    print("==================================================")
    print("SENTINEL - IEEE Paper Figures Capture Suite")
    print("==================================================")

    # Step 1: Create figures/ directories
    os.makedirs(WORKSPACE_FIGURES, exist_ok=True)
    os.makedirs(PROJECT_FIGURES, exist_ok=True)
    print(f"[+] Verified target folders:\n    1. {WORKSPACE_FIGURES}\n    2. {PROJECT_FIGURES}")

    # Step 2: Authenticate session
    s = requests.Session()
    r_login = s.post(
        "http://127.0.0.1:8000/login",
        data={"username": settings.ADMIN_USERNAME, "password": settings.ADMIN_PASSWORD},
        allow_redirects=True
    )
    assert r_login.status_code == 200, f"Login failed: HTTP {r_login.status_code}"
    print("[+] Successfully authenticated as SOC administrator.")

    captured_files = []
    for target in TARGETS:
        # Capture into PROJECT_FIGURES
        out_path = capture_page(s, target, PROJECT_FIGURES)
        # Also copy to WORKSPACE_FIGURES
        ws_copy = os.path.join(WORKSPACE_FIGURES, target["filename"])
        shutil.copyfile(out_path, ws_copy)
        captured_files.append((target["filename"], out_path))

    print("\n==================================================")
    print("VALIDATION & INTEGRITY CHECKS")
    print("==================================================")

    # Check 01_system_architecture.png is untouched
    for d in [PROJECT_FIGURES, WORKSPACE_FIGURES]:
        arch_img = os.path.join(d, "01_system_architecture.png")
        if os.path.exists(arch_img):
            print(f"[!] Note: 01_system_architecture.png exists in {d} (preserved).")
        else:
            print(f"[PASS] 01_system_architecture.png was NOT generated or overwritten in {d} (left for manual addition).")

    print(f"[PASS] Total figures captured: {len(captured_files)}/4")

if __name__ == "__main__":
    main()
