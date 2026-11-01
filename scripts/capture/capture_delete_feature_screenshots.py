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

    # 2. Capture Active Cases Overview (with Investigate & Delete buttons)
    r_overview = s.get("http://127.0.0.1:8000/incidents?tab=active")
    html_active = r_overview.text
    if "<head>" in html_active:
        html_active = html_active.replace("<head>", '<head><base href="http://127.0.0.1:8000/">')

    capture_html(html_active, "docs/screenshots/04_incident_ledger_1366.png", width=1366, height=850)
    capture_html(html_active, "docs/screenshots/04_incident_ledger_1440.png", width=1440, height=900)

    # 3. Capture Delete Confirmation Modal open state
    modal_style = """
    <style>
        #deleteIncidentModal1 { display: block !important; opacity: 1 !important; z-index: 1055 !important; }
        .modal-backdrop-custom { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(0,0,0,0.7); z-index: 1050; }
    </style>
    <div class="modal-backdrop-custom"></div>
    """
    html_modal = html_active.replace('id="deleteIncidentModal1"', 'id="deleteIncidentModal1" class="modal fade show"')
    html_modal = html_modal.replace('</body>', f'{modal_style}</body>')
    capture_html(html_modal, "docs/screenshots/06_incident_delete_modal_1366.png", width=1366, height=850)

    # 4. Soft-delete Incident #2 for demonstration of Deleted Cases tab
    r_del2 = s.post("http://127.0.0.1:8000/incidents/2/delete", allow_redirects=False)
    print("Soft-deleted incident #2:", r_del2.status_code, "Redirect:", r_del2.headers.get("location"))

    # Capture Active Ledger with deletion notification banner
    r_post_del = s.get("http://127.0.0.1:8000/incidents?msg=Incident+%232+deleted+successfully.")
    html_post_del = r_post_del.text
    if "<head>" in html_post_del:
        html_post_del = html_post_del.replace("<head>", '<head><base href="http://127.0.0.1:8000/">')
    capture_html(html_post_del, "docs/screenshots/04_incident_ledger_deleted_banner_1366.png", width=1366, height=850)

    # 5. Capture Deleted Cases Tab (/incidents?tab=deleted)
    r_deleted_tab = s.get("http://127.0.0.1:8000/incidents?tab=deleted")
    html_deleted = r_deleted_tab.text
    if "<head>" in html_deleted:
        html_deleted = html_deleted.replace("<head>", '<head><base href="http://127.0.0.1:8000/">')
    capture_html(html_deleted, "docs/screenshots/04_incident_deleted_cases_1366.png", width=1366, height=850)
    capture_html(html_deleted, "docs/screenshots/04_incident_deleted_cases_1440.png", width=1440, height=900)

    # 6. Restore Incident #2 to leave database clean and restored
    r_restore = s.post("http://127.0.0.1:8000/incidents/2/restore", allow_redirects=False)
    print("Restored incident #2:", r_restore.status_code, "Redirect:", r_restore.headers.get("location"))

    # 7. Capture Incident Detail for Incident #1 (showing Delete Incident buttons)
    r_detail = s.get("http://127.0.0.1:8000/incidents/1")
    html_detail = r_detail.text
    if "<head>" in html_detail:
        html_detail = html_detail.replace("<head>", '<head><base href="http://127.0.0.1:8000/">')

    capture_html(html_detail, "docs/screenshots/05_incident_detail_1366.png", width=1366, height=900)
    capture_html(html_detail, "docs/screenshots/05_incident_detail_1440.png", width=1440, height=950)

    print("\nAll Delete & Restore screenshots captured and verified successfully.")

if __name__ == "__main__":
    main()
