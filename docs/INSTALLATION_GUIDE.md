# SENTINEL // Installation & Deployment Guide

## 1. System Requirements

### Workstation Specifications
- **Operating System:** Windows 10, Windows 11, or Windows Server 2022 (x64)
- **Processor:** 2.0 GHz quad-core 64-bit CPU or higher
- **RAM:** Minimum 4 GB (8 GB recommended for simultaneous ingestion and analytics)
- **Disk Space:** 500 MB free space (plus database storage; baseline DB is ~16 MB)
- **Python Version:** Python 3.11, 3.12, or 3.13

---

## 2. Windows Native Installation (Standard)

### Step 1: Extract Workspace
Extract the project archive to your desired location, e.g.:
```powershell
C:\SENTINEL\threat_intel_platform
```

### Step 2: Initialize Virtual Environment
Open PowerShell in the project directory:
```powershell
cd C:\SENTINEL\threat_intel_platform
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
Ensure pip is up to date and install all production packages:
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
Edit `.env` to configure your administrator credentials and optional keys:
```ini
ADMIN_USERNAME=admin
ADMIN_PASSWORD=YourStrongPassword#2026!
SECRET_KEY=generate-a-strong-secret-key-32-chars-long
DEV_AUTO_LOGIN=False

# AlienVault OTX API Key (Optional)
OTX_API_KEY=

# Automated Lifecycle
IOC_TTL_DAYS=30
SCHEDULER_INTERVAL_MINUTES=360
```

### Step 5: Start the Platform
Double-click `start.bat` or run:
```powershell
python run.py
```
Uvicorn will automatically bind to `127.0.0.1:8000` (or the next available port) and launch the web interface in your browser.

---

## 3. Docker Containerized Deployment (Alternative)

For containerized deployment on systems with Docker Desktop:

### Step 1: Review Configuration
Ensure `docker-compose.yml` reflects your desired ports and volume paths.

### Step 2: Build and Run
```bash
docker compose up -d --build
```

### Step 3: Verify Container Health
```bash
docker compose ps
docker compose logs -f
```

### Step 4: Access Application
Navigate to `http://localhost:8000`.

---

## 4. Verification Check
After launch, confirm proper initialization:
```powershell
.\.venv\Scripts\python.exe tests/test_match.py
```
Output should confirm: `Loaded 39522 IOCs. Total Matches: 8`.

