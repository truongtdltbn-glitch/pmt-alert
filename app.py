import os
import requests
import sys
import json

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from database import get_db, init_db, cleanup_old_logs
from scheduler import run_alert_check, query_prometheus
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = "pmt-alert-dashboard-secret-key"

scheduler = BackgroundScheduler()

def load_jobs_from_db():
    """Reload scheduler jobs from active configurations in database."""
    scheduler.remove_all_jobs()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, interval_minutes FROM alert_configs WHERE status = 'active'")
    configs = cursor.fetchall()
    cursor.close()
    conn.close()

    for config in configs:
        job_id = f"alert_job_{config['id']}"
        interval = config['interval_minutes']
        scheduler.add_job(
            func=run_alert_check,
            trigger=IntervalTrigger(minutes=interval),
            args=[config['id']],
            id=job_id,
            name=f"Check rule: {config['name']}",
            replace_existing=True
        )
        print(f"Scheduled alert job for '{config['name']}' every {interval} minutes.")

    # Schedule daily log cleanup
    scheduler.add_job(
        func=cleanup_old_logs,
        trigger='cron',
        hour=3,
        minute=0,
        id='log_cleanup',
        name='Daily log cleanup (7d)',
        replace_existing=True,
        kwargs={'days': 7}
    )

# --- Authentication Middleware & Routes ---
@app.before_request
def require_login():
    if request.endpoint in ('login', 'static'):
        return
    if not session.get('logged_in'):
        return redirect(url_for('login'))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == "admin" and password == "PGBank@2026devops":
            session['logged_in'] = True
            flash("Welcome to Prometheus Alert Dashboard!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Incorrect username or password.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    flash("You have logged out successfully.", "success")
    return redirect(url_for("login"))

@app.context_processor
def inject_active_page():
    return dict(active_page=request.path.split('/')[1] or 'dashboard')

# --- Routes ---

@app.route("/")
def dashboard():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT c.*, p.name as prom_name, s.current_state, s.last_triggered_count, s.last_checked_at
        FROM alert_configs c
        LEFT JOIN prometheus_connections p ON c.prometheus_id = p.id
        LEFT JOIN alert_states s ON c.id = s.alert_config_id
        ORDER BY c.created_at DESC
    """)
    configs = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) as total FROM alert_logs WHERE created_at > NOW() - INTERVAL '1 day'")
    recent_alerts = cursor.fetchone()['total']
    
    cursor.close()
    conn.close()
    
    return render_template("dashboard.html", configs=configs, recent_alerts=recent_alerts)

@app.route("/alerts", methods=["GET"])
def alerts():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT l.*, c.name as alert_name
        FROM alert_logs l
        JOIN alert_configs c ON l.alert_config_id = c.id
        ORDER BY l.created_at DESC
        LIMIT %s OFFSET %s
    """, (per_page, offset))
    logs = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) as total FROM alert_logs")
    total = cursor.fetchone()['total']
    
    cursor.close()
    conn.close()
    
    total_pages = (total + per_page - 1) // per_page
    return render_template("alerts.html", logs=logs, page=page, total_pages=total_pages)

@app.route("/connections", methods=["GET", "POST", "DELETE"])
def connections():
    if request.method == "POST":
        name = request.form.get("name")
        url = request.form.get("url")
        
        if not name or not url:
            flash("Name and URL are required.", "error")
            return redirect(url_for("connections"))
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO prometheus_connections (name, url) VALUES (%s, %s)", (name, url))
        conn.commit()
        conn.close()
        flash(f"Prometheus connection '{name}' added successfully.", "success")
        return redirect(url_for("connections"))
    
    elif request.method == "DELETE":
        conn_id = request.json.get("id")
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM prometheus_connections WHERE id = %s", (conn_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"})
    
    # GET
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM prometheus_connections ORDER BY created_at DESC")
    conns = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("connections.html", connections=conns)

@app.route("/alert-config", methods=["GET", "POST", "DELETE"])
def alert_config():
    if request.method == "POST":
        data = {
            'name': request.form.get("name"),
            'app_name': request.form.get("app_name"),
            'prometheus_id': request.form.get("prometheus_id"),
            'query_string': request.form.get("query_string"),
            'interval_minutes': request.form.get("interval_minutes", 5, type=int),
            'warning_threshold': request.form.get("warning_threshold", 1, type=float),
            'critical_threshold': request.form.get("critical_threshold", 5, type=float),
            'msteams_webhook': request.form.get("msteams_webhook"),
            'payload_name': request.form.get("payload_name"),
            'payload_error': request.form.get("payload_error"),
            'payload_detail': request.form.get("payload_detail"),
            'payload_action': request.form.get("payload_action"),
            'payload_grafana': request.form.get("payload_grafana"),
        }
        
        if not all([data['name'], data['prometheus_id'], data['query_string'], data['msteams_webhook']]):
            flash("All required fields must be filled.", "error")
            return redirect(url_for("alert_config"))
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alert_configs 
            (name, app_name, prometheus_id, query_string, interval_minutes, warning_threshold, 
             critical_threshold, msteams_webhook, payload_name, payload_error, payload_detail, 
             payload_action, payload_grafana)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, tuple(data.values()))
        
        # Initialize alert state
        config_id = cursor.fetchone()['id']
        cursor.execute("INSERT INTO alert_states (alert_config_id) VALUES (%s)", (config_id,))
        conn.commit()
        conn.close()
        
        # Reload scheduler
        load_jobs_from_db()
        
        flash(f"Alert config '{data['name']}' created successfully.", "success")
        return redirect(url_for("dashboard"))
    
    elif request.method == "DELETE":
        config_id = request.json.get("id")
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alert_configs WHERE id = %s", (config_id,))
        cursor.execute("DELETE FROM alert_states WHERE alert_config_id = %s", (config_id,))
        cursor.execute("DELETE FROM alert_logs WHERE alert_config_id = %s", (config_id,))
        conn.commit()
        conn.close()
        load_jobs_from_db()
        return jsonify({"status": "ok"})
    
    # GET
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM prometheus_connections")
    connections = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("alert_config.html", connections=connections)

@app.route("/logs/<int:config_id>")
def logs(config_id):
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM alert_logs 
        WHERE alert_config_id = %s
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
    """, (config_id, per_page, offset))
    logs = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) as total FROM alert_logs WHERE alert_config_id = %s", (config_id,))
    total = cursor.fetchone()['total']
    
    cursor.close()
    conn.close()
    
    total_pages = (total + per_page - 1) // per_page
    return render_template("logs.html", logs=logs, config_id=config_id, page=page, total_pages=total_pages)

@app.route("/test-prometheus", methods=["POST"])
def test_prometheus():
    prometheus_url = request.json.get("url")
    query_string = request.json.get("query")
    
    value, error = query_prometheus(prometheus_url, query_string)
    
    if error:
        return jsonify({"status": "error", "message": error}), 400
    else:
        return jsonify({"status": "ok", "value": value})

if __name__ == "__main__":
    init_db()
    load_jobs_from_db()
    scheduler.start()
    app.run(host="0.0.0.0", port=5000, debug=False)
