"""
database.py
SQLite persistence layer for the Threat Intel Platform.
Tables: iocs, alerts
"""

import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_FILE = "threat_intel.db"


# ── Connection ────────────────────────────────────────────────────────────────

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # better concurrent access
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ── Schema ────────────────────────────────────────────────────────────────────

def init_db():
    """Creates all tables and indexes if they don't already exist."""
    conn = get_connection()
    c = conn.cursor()

    # 1. Threat Intel IOCs
    c.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc_value        TEXT UNIQUE NOT NULL,
        ioc_type         TEXT NOT NULL,          -- ip, domain, url, email, md5, sha1, sha256
        threat_type      TEXT,                   -- botnet, c2, malware, phishing, spam
        malware_family   TEXT,                   -- e.g. Emotet, Cobalt Strike
        confidence_score INTEGER DEFAULT 75,
        severity         TEXT    DEFAULT 'medium', -- low, medium, high, critical
        source           TEXT    NOT NULL,        -- ThreatFox, URLhaus, MalwareBazaar …
        tags             TEXT,                   -- JSON list of free-form tags
        first_seen       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        hit_count        INTEGER DEFAULT 0        -- times this IOC triggered an alert
    );
    """)

    # Indexes for fast O(1) lookups during log correlation
    c.execute("CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs (ioc_value);")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ioc_type  ON iocs (ioc_type);")

    # 2. Correlated Alerts — unique constraint prevents duplicate alerts
    c.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        matched_ioc      TEXT NOT NULL,
        ioc_type         TEXT NOT NULL,
        threat_type      TEXT,
        malware_family   TEXT,
        severity         TEXT NOT NULL,
        confidence_score INTEGER,
        log_source       TEXT,
        raw_log_line     TEXT NOT NULL,
        attack_technique TEXT,                   -- MITRE ATT&CK technique ID
        attack_name      TEXT,                   -- MITRE ATT&CK technique name
        UNIQUE (matched_ioc, raw_log_line)       -- prevents duplicate alerts
    );
    """)

    conn.commit()
    conn.close()


# ── Migrations (add columns to existing DBs) ─────────────────────────────────

def run_migrations():
    """Safely add new columns to existing databases without data loss."""
    conn = get_connection()
    c = conn.cursor()
    new_columns = [
        ("iocs",   "tags",             "TEXT"),
        ("iocs",   "last_seen",        "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("iocs",   "hit_count",        "INTEGER DEFAULT 0"),
        ("alerts", "attack_technique", "TEXT"),
        ("alerts", "attack_name",      "TEXT"),
    ]
    for table, col, col_type in new_columns:
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
        except sqlite3.OperationalError:
            pass   # column already exists
    conn.commit()
    conn.close()


# ── IOC CRUD ──────────────────────────────────────────────────────────────────

def insert_ioc(ioc_dict: Dict[str, Any]) -> bool:
    """
    Inserts a new IOC or updates last_seen on a duplicate.
    Returns True if a new row was inserted.
    """
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""
        INSERT INTO iocs
            (ioc_value, ioc_type, threat_type, malware_family,
             confidence_score, severity, source, tags)
        VALUES
            (:ioc_value, :ioc_type, :threat_type, :malware_family,
             :confidence_score, :severity, :source, :tags)
        ON CONFLICT(ioc_value) DO UPDATE SET
            last_seen        = CURRENT_TIMESTAMP,
            confidence_score = MAX(confidence_score, excluded.confidence_score)
        """, {
            "ioc_value":        ioc_dict.get("ioc_value", ""),
            "ioc_type":         ioc_dict.get("ioc_type", "unknown"),
            "threat_type":      ioc_dict.get("threat_type", "unknown"),
            "malware_family":   ioc_dict.get("malware_family", "Unknown"),
            "confidence_score": ioc_dict.get("confidence_score", 75),
            "severity":         ioc_dict.get("severity", "medium"),
            "source":           ioc_dict.get("source", "Manual"),
            "tags":             ioc_dict.get("tags", None),
        })
        conn.commit()
        return c.rowcount > 0
    finally:
        conn.close()


def get_all_iocs(limit: int = 500, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection()
    c = conn.cursor()
    if ioc_type:
        c.execute(
            "SELECT * FROM iocs WHERE ioc_type=? ORDER BY last_seen DESC LIMIT ?",
            (ioc_type, limit)
        )
    else:
        c.execute("SELECT * FROM iocs ORDER BY last_seen DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_ioc_count() -> int:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM iocs")
    count = c.fetchone()[0]
    conn.close()
    return count


def get_ioc_type_distribution() -> Dict[str, int]:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT ioc_type, COUNT(*) as cnt FROM iocs GROUP BY ioc_type ORDER BY cnt DESC")
    result = {row["ioc_type"]: row["cnt"] for row in c.fetchall()}
    conn.close()
    return result


# ── Alert CRUD ────────────────────────────────────────────────────────────────

def save_alert(alert_dict: Dict[str, Any]) -> bool:
    """
    Persists a new alert. Silently ignores duplicates (same IOC + same log line).
    Also increments the hit_count on the matched IOC.
    Returns True if alert was newly inserted.
    """
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""
        INSERT OR IGNORE INTO alerts
            (matched_ioc, ioc_type, threat_type, malware_family, severity,
             confidence_score, log_source, raw_log_line, attack_technique, attack_name)
        VALUES
            (:matched_ioc, :ioc_type, :threat_type, :malware_family, :severity,
             :confidence_score, :log_source, :raw_log_line, :attack_technique, :attack_name)
        """, {
            "matched_ioc":      alert_dict.get("matched_ioc"),
            "ioc_type":         alert_dict.get("ioc_type"),
            "threat_type":      alert_dict.get("threat_type"),
            "malware_family":   alert_dict.get("malware_family"),
            "severity":         alert_dict.get("severity"),
            "confidence_score": alert_dict.get("confidence_score"),
            "log_source":       alert_dict.get("log_source"),
            "raw_log_line":     alert_dict.get("raw_log_line"),
            "attack_technique": alert_dict.get("attack_technique"),
            "attack_name":      alert_dict.get("attack_name"),
        })
        inserted = c.rowcount > 0
        if inserted:
            # Bump hit_count on the triggering IOC
            c.execute(
                "UPDATE iocs SET hit_count = hit_count + 1 WHERE ioc_value = ?",
                (alert_dict.get("matched_ioc"),)
            )
        conn.commit()
        return inserted
    finally:
        conn.close()


def get_all_alerts(limit: int = 100, severity: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection()
    c = conn.cursor()
    if severity:
        c.execute(
            "SELECT * FROM alerts WHERE severity=? ORDER BY timestamp DESC LIMIT ?",
            (severity, limit)
        )
    else:
        c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_alert_count() -> int:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM alerts")
    count = c.fetchone()[0]
    conn.close()
    return count


def get_alert_severity_distribution() -> Dict[str, int]:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity ORDER BY cnt DESC")
    result = {row["severity"]: row["cnt"] for row in c.fetchall()}
    conn.close()
    return result


def get_alerts_daily_trend(days: int = 7) -> List[Dict[str, Any]]:
    """Returns alert counts grouped by day for the last N days."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT DATE(timestamp) as day, COUNT(*) as count
        FROM   alerts
        WHERE  timestamp >= DATE('now', ?)
        GROUP  BY DATE(timestamp)
        ORDER  BY day ASC
    """, (f"-{days} days",))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_top_malware_families(limit: int = 10) -> List[Dict[str, Any]]:
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT malware_family, COUNT(*) as hits, MAX(severity) as max_severity
        FROM   alerts
        GROUP  BY malware_family
        ORDER  BY hits DESC
        LIMIT  ?
    """, (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# ── Bootstrap ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    run_migrations()
    print("[+] Database initialized and migrations applied.")