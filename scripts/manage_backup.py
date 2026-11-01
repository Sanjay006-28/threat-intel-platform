import os
import sys
import time
import sqlite3
import hashlib
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.abspath(os.path.join(BASE_DIR, "threat_intel.db"))
BACKUP_DIR = os.path.abspath(os.path.join(BASE_DIR, "backups"))

def calculate_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def get_db_metrics(db_path: str):
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        iocs = cursor.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        alerts = cursor.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        events = cursor.execute("SELECT COUNT(*) FROM log_events").fetchone()[0]
        users = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        feeds = cursor.execute("SELECT COUNT(*) FROM feeds").fetchone()[0]
        integrity = cursor.execute("PRAGMA quick_check").fetchone()[0]
        return {
            "iocs": iocs,
            "alerts": alerts,
            "log_events": events,
            "users": users,
            "feeds": feeds,
            "integrity": integrity
        }

def perform_backup(target_path: str = None, retention: int = 5) -> str:
    if not os.path.exists(DB_FILE):
        raise FileNotFoundError(f"Source database not found at {DB_FILE}")

    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_file = target_path or os.path.join(BACKUP_DIR, f"sentinel_backup_{timestamp}.db")

    print(f"[*] Initiating SQLite online backup...")
    print(f"    Source: {DB_FILE}")
    print(f"    Target: {backup_file}")

    # 1. Connect and flush WAL to main database file
    with sqlite3.connect(DB_FILE) as src_conn:
        src_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        
        # 2. Use atomic SQLite Online Backup API
        with sqlite3.connect(backup_file) as dest_conn:
            src_conn.backup(dest_conn, pages=100)

    # 3. Verify backup database
    src_metrics = get_db_metrics(DB_FILE)
    dest_metrics = get_db_metrics(backup_file)

    assert dest_metrics["integrity"] == "ok", "Backup failed SQLite integrity check!"
    assert dest_metrics["iocs"] == src_metrics["iocs"], f"IOC mismatch: {dest_metrics['iocs']} vs {src_metrics['iocs']}"
    assert dest_metrics["alerts"] == src_metrics["alerts"], f"Alert mismatch: {dest_metrics['alerts']} vs {src_metrics['alerts']}"

    file_size_mb = os.path.getsize(backup_file) / (1024 * 1024)
    sha256_hash = calculate_sha256(backup_file)

    print(f"[+] Backup completed successfully!")
    print(f"    File:       {backup_file}")
    print(f"    Size:       {file_size_mb:.2f} MB")
    print(f"    SHA-256:    {sha256_hash}")
    print(f"    IOCs:       {dest_metrics['iocs']:,}")
    print(f"    Alerts:     {dest_metrics['alerts']:,}")
    print(f"    Integrity:  {dest_metrics['integrity'].upper()}")

    # Apply backup retention rotation
    rotate_backups(keep_count=retention)
    return backup_file

def rotate_backups(keep_count: int = 5):
    """Retains the most recent N backups, pruning older snapshots across backups/ and root."""
    backups = []
    for directory in [BACKUP_DIR, BASE_DIR]:
        if not os.path.exists(directory):
            continue
        for f in os.listdir(directory):
            if f.startswith("sentinel_backup_") and f.endswith(".db"):
                fp = os.path.join(directory, f)
                backups.append((os.path.getmtime(fp), fp))
    backups.sort(reverse=True)
    if len(backups) > keep_count:
        for _, old_backup in backups[keep_count:]:
            try:
                os.remove(old_backup)
                print(f"[*] Pruned expired backup: {os.path.basename(old_backup)}")
            except Exception as e:
                print(f"[!] Warning deleting old backup {old_backup}: {e}")

def perform_restore(backup_file: str, target_db: str = None) -> bool:
    target_path = target_db or DB_FILE
    if not os.path.exists(backup_file):
        raise FileNotFoundError(f"Backup file not found at {backup_file}")

    print(f"[*] Initiating SQLite restoration...")
    print(f"    Source Backup: {backup_file}")
    print(f"    Target DB:     {target_path}")

    # Verify backup integrity first
    backup_metrics = get_db_metrics(backup_file)
    if backup_metrics["integrity"] != "ok":
        raise ValueError(f"Corrupt backup file! Integrity check: {backup_metrics['integrity']}")

    # Restore via SQLite backup API
    with sqlite3.connect(backup_file) as src_conn:
        with sqlite3.connect(target_path) as dest_conn:
            src_conn.backup(dest_conn, pages=100)
            dest_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    target_metrics = get_db_metrics(target_path)
    print(f"[+] Restoration completed successfully!")
    print(f"    Target:     {target_path}")
    print(f"    IOCs:       {target_metrics['iocs']:,}")
    print(f"    Alerts:     {target_metrics['alerts']:,}")
    print(f"    Integrity:  {target_metrics['integrity'].upper()}")
    return True

def main():
    parser = argparse.ArgumentParser(description="SENTINEL Database Backup & Recovery Utility")
    parser.add_argument("action", choices=["backup", "restore", "verify"], help="Action to execute")
    parser.add_argument("--file", help="Path to backup file (for restore or custom backup target)")
    parser.add_argument("--retention", type=int, default=5, help="Number of backups to retain (default: 5)")

    args = parser.parse_args()

    if args.action == "backup":
        perform_backup(args.file, retention=args.retention)
    elif args.action == "restore":
        if not args.file:
            print("Error: --file argument is required for restore.")
            sys.exit(1)
        perform_restore(args.file)
    elif args.action == "verify":
        target = args.file or DB_FILE
        print(f"Checking {target}...")
        metrics = get_db_metrics(target)
        for k, v in metrics.items():
            print(f"  {k}: {v}")

if __name__ == "__main__":
    main()

