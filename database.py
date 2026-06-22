import psycopg2
from psycopg2.extras import RealDictCursor
import os
import json
from datetime import datetime, timedelta

PG_HOST = os.environ.get("PG_HOST", "10.75.48.100")
PG_PORT = os.environ.get("PG_PORT", "5432")
PG_USER = os.environ.get("PG_USER", "admin")
PG_PASS = os.environ.get("PG_PASS", "Admin@123")
PG_DB   = os.environ.get("PG_DB",   "pmt-alert")

def get_db():
    """Return a psycopg2 connection with RealDictCursor for dict-like access."""
    conn = psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        user=PG_USER,
        password=PG_PASS,
        dbname=PG_DB,
        cursor_factory=RealDictCursor
    )
    return conn

def init_db():
    """Initialize database tables."""
    conn = get_db()
    cursor = conn.cursor()

    # Prometheus Connections table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS prometheus_connections (
        id          SERIAL PRIMARY KEY,
        name        TEXT NOT NULL,
        url         TEXT NOT NULL,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Alert Configurations table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alert_configs (
        id                   SERIAL PRIMARY KEY,
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
        id                  SERIAL PRIMARY KEY,
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
        id                  SERIAL PRIMARY KEY,
        alert_config_id     INTEGER NOT NULL,
        alert_state         TEXT,
        query_result_count  REAL,
        threshold           REAL,
        message             TEXT,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (alert_config_id) REFERENCES alert_configs(id)
    )
    """)

    # Server Configurations table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS server_configs (
        id                      SERIAL PRIMARY KEY,
        name                    TEXT NOT NULL UNIQUE,
        target                  TEXT,
        prometheus_id           INTEGER NOT NULL,
        cpu_query               TEXT,
        memory_query            TEXT,
        disk_query              TEXT,
        cpu_warning_threshold   REAL DEFAULT 70,
        cpu_critical_threshold  REAL DEFAULT 90,
        memory_warning_threshold REAL DEFAULT 75,
        memory_critical_threshold REAL DEFAULT 90,
        disk_warning_threshold  REAL DEFAULT 80,
        disk_critical_threshold REAL DEFAULT 95,
        msteams_webhook         TEXT NOT NULL,
        status                  TEXT DEFAULT 'active',
        created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (prometheus_id) REFERENCES prometheus_connections(id)
    )
    """)

    # Server Metrics table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS server_metrics (
        id                  SERIAL PRIMARY KEY,
        server_config_id    INTEGER NOT NULL,
        metric_type         TEXT,
        metric_value        REAL,
        current_state       TEXT DEFAULT 'ok',
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (server_config_id) REFERENCES server_configs(id)
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
    cursor.execute("DELETE FROM alert_logs WHERE created_at < %s", (cutoff_date,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    print(f"Cleaned up {deleted} old alert logs (older than {days} days)")
    return deleted
