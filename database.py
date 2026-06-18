import sqlite3
import os
import json
from datetime import datetime, timedelta

DB_PATH = os.environ.get("DB_PATH", "pmt_alert.db")

def get_db():
    """Return a sqlite3 connection with row factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables."""
    conn = get_db()
    cursor = conn.cursor()

    # Prometheus Connections table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS prometheus_connections (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        url         TEXT NOT NULL,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Alert Configurations table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alert_configs (
        id                   INTEGER PRIMARY KEY AUTOINCREMENT,
        name                 TEXT NOT NULL,
        app_name             TEXT,
        prometheus_id        INTEGER NOT NULL,
        query_string         TEXT NOT NULL,
        interval_minutes     INTEGER DEFAULT 5,
        warning_threshold    REAL NOT NULL DEFAULT 1,
        critical_threshold   REAL NOT NULL DEFAULT 5,
        msteams_webhook      TEXT NOT NULL,
        payload_name         TEXT NOT NULL,
        payload_error        TEXT NOT NULL,
        payload_detail       TEXT NOT NULL,
        payload_action       TEXT NOT NULL,
        payload_grafana      TEXT NOT NULL,
        status               TEXT DEFAULT 'active',
        created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (prometheus_id) REFERENCES prometheus_connections(id)
    )
    """)

    # Alert States table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alert_states (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_config_id     INTEGER NOT NULL,
        current_state       TEXT DEFAULT 'ok',
        last_triggered_count INTEGER DEFAULT 0,
        last_checked_at     TIMESTAMP,
        last_triggered_at   TIMESTAMP,
        FOREIGN KEY (alert_config_id) REFERENCES alert_configs(id)
    )
    """)

    # Alert Logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alert_logs (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_config_id     INTEGER NOT NULL,
        alert_state         TEXT,
        query_result_count  REAL,
        threshold           REAL,
        message             TEXT,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (alert_config_id) REFERENCES alert_configs(id)
    )
    """)

    conn.commit()
    conn.close()
    print("Database initialized successfully!")

def cleanup_old_logs(days=7):
    """Delete alert logs older than specified days."""
    conn = get_db()
    cursor = conn.cursor()
    cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
    cursor.execute("DELETE FROM alert_logs WHERE created_at < ?", (cutoff_date,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    print(f"Cleaned up {deleted} old alert logs (older than {days} days)")
    return deleted
