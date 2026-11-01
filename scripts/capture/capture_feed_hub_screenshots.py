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

    # 2. Get Threat Feed Hub Page
    r_feeds = s.get("http://127.0.0.1:8000/feeds")
    assert r_feeds.status_code == 200

    # 3. Capture at Laptop Resolutions: 1366x768, 1440x900, 1600x900
    capture_html(r_feeds.text, "docs/screenshots/08_threat_feed_hub_1366.png", 1366, 850)
    capture_html(r_feeds.text, "docs/screenshots/08_threat_feed_hub_1440.png", 1440, 900)
    capture_html(r_feeds.text, "docs/screenshots/08_threat_feed_hub_1600.png", 1600, 900)

    print("\n[+] All Threat Feed Hub screenshots captured successfully.")

if __name__ == "__main__":
    main()

