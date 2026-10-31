# SENTINEL // Database Backup & Disaster Recovery Guide

## 1. Overview
SENTINEL utilizes SQLite 3 running in Write-Ahead Logging mode (`PRAGMA journal_mode=WAL`). Because WAL mode separates read operations from sequential write commits across `threat_intel.db`, `threat_intel.db-wal`, and `threat_intel.db-shm`, standard file copy operations can result in incomplete or corrupted snapshots if a transaction is in-flight.

To guarantee atomic point-in-time consistency without taking the platform offline, SENTINEL provides [manage_backup.py](file:///c:/Users/dsanj/Downloads/threat_intel_platform/threat_intel_platform/manage_backup.py), utilizing the official **SQLite Online Backup API** and WAL checkpointing.

---

## 2. Backup Architecture & Workflow
When a backup is triggered:
1. **WAL Checkpointing:** Executes `PRAGMA wal_checkpoint(TRUNCATE)` to flush all cached write-ahead transactions into the primary database file.
2. **Online Snapshot:** Utilizes `sqlite3.connect().backup()` to stream database pages atomically into the destination file.
3. **Integrity Verification:** Executes `PRAGMA quick_check` on the newly created backup.
4. **Data Verification:** Compares record counts (`iocs`, `alerts`, `log_events`, `users`, `feeds`) between the live database and backup file.
5. **Checksum & Size:** Calculates the SHA-256 cryptographic digest and reports size metrics.
6. **Retention Policy:** Automatically prunes snapshots older than the configured retention threshold (default: 5 most recent backups).

---

## 3. Step-by-Step Operational Instructions

### A. Creating a Backup
To create a timestamped backup:
```powershell
python manage_backup.py backup
```
**Example Output:**
```
[*] Initiating SQLite online backup...
    Source: C:\SENTINEL\threat_intel_platform\threat_intel.db
    Target: C:\SENTINEL\threat_intel_platform\sentinel_backup_20261030_233458.db
[+] Backup completed successfully!
    File:       C:\SENTINEL\threat_intel_platform\sentinel_backup_20261030_233458.db
    Size:       15.22 MB
    SHA-256:    a67ae8f3dda6203d90884e658a28f9f7901fbe1dcb9f1f80f01ae0b40a00a08c
    IOCs:       39,522
    Alerts:     20
    Integrity:  OK
```

### B. Custom Target and Retention Control
To specify a custom backup path and retention limit:
```powershell
python manage_backup.py backup --file C:\Backups\sentinel_custom.db --retention 10
```

### C. Verifying Database Integrity
To check the structural integrity and record counts of any database file:
```powershell
python manage_backup.py verify --file sentinel_backup_20261030_233458.db
```

### D. Disaster Recovery (Restoration)
To restore SENTINEL to a known good backup:

1. **Stop Application Server:** Press `Ctrl+C` in the running Uvicorn/terminal window.
2. **Execute Restore:**
   ```powershell
   python manage_backup.py restore --file sentinel_backup_20261030_233458.db
   ```
3. **Verify Integrity:**
   ```powershell
   python manage_backup.py verify
   ```
4. **Restart Platform:** Run `start.bat` or `python run.py`.

