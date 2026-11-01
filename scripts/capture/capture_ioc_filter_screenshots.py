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
    # Fix relative asset links if necessary so styles render in local file
    processed_html = html_content.replace('href="/static/', 'href="http://127.0.0.1:8000/static/')
    processed_html = processed_html.replace('src="/static/', 'src="http://127.0.0.1:8000/static/')
    
    with open(temp_html, "w", encoding="utf-8") as f:
        f.write(processed_html)

    screenshot_path = os.path.abspath(output_filename)
    os.makedirs(os.path.dirname(screenshot_path), exist_ok=True)

    cmd = [
        CHROME_PATH,
        "--headless=new",
        "--disable-gpu",
        "--virtual-time-budget=3000",
        f"--window-size={width},{height}",
        f"--screenshot={screenshot_path}",
        temp_html
    ]
    subprocess.run(cmd, timeout=30, check=True)
    size = os.path.getsize(screenshot_path)
    print(f"[+] Saved {output_filename} ({width}x{height}) - {size:,} bytes")

    if os.path.exists(temp_html):
        os.remove(temp_html)

    # Mirror to artifact directory
    artifact_dest = os.path.join(ARTIFACT_DIR, os.path.basename(output_filename))
    shutil.copyfile(screenshot_path, artifact_dest)
    print(f"    -> Mirrored to artifact directory: {artifact_dest}")

def main():
    s = requests.Session()
    # 1. Login
    r_login = s.post(
        "http://127.0.0.1:8000/login",
        data={"username": settings.ADMIN_USERNAME, "password": settings.ADMIN_PASSWORD},
        allow_redirects=False
    )
    print("Login status:", r_login.status_code)
    assert r_login.status_code in [302, 303], "Login failed"

    # 2. Capture Filtered IOC Repository (e.g. Type=IPv4, Status=Active) at 1366, 1440, 1600
    r_filtered = s.get("http://127.0.0.1:8000/iocs?type=ipv4&status=active")
    assert r_filtered.status_code == 200
    capture_html(r_filtered.text, "docs/screenshots/07_ioc_repository_filtered_1366.png", 1366, 768)
    capture_html(r_filtered.text, "docs/screenshots/07_ioc_repository_filtered_1440.png", 1440, 900)
    capture_html(r_filtered.text, "docs/screenshots/07_ioc_repository_filtered_1600.png", 1600, 900)

    # 3. Capture Combined Filter (Search q=194.26 + Type=IPv4 + Status=Active)
    r_combined = s.get("http://127.0.0.1:8000/iocs?q=194.26&type=ipv4&status=active")
    assert r_combined.status_code == 200
    capture_html(r_combined.text, "docs/screenshots/07_ioc_repository_combined_1366.png", 1366, 768)

    # 4. Capture Unfiltered Repository Overview at 1366x768
    r_unfiltered = s.get("http://127.0.0.1:8000/iocs")
    assert r_unfiltered.status_code == 200
    capture_html(r_unfiltered.text, "docs/screenshots/07_ioc_repository_overview_1366.png", 1366, 768)

    print("\n[+] All IOC Repository screenshots captured successfully.")

if __name__ == "__main__":
    main()

