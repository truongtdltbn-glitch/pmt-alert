import os
import requests
import sys
import json

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from database import get_db, init_db, cleanup_old_logs, migrate_add_target_column, migrate_add_payload_columns
from scheduler import run_alert_check, run_server_monitoring_check, query_prometheus
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
    
    # Load alert checking jobs
    cursor.execute("SELECT id, name, interval_minutes FROM alert_configs WHERE status = 'active'")
    configs = cursor.fetchall()

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

    # Load server monitoring jobs
    cursor.execute("SELECT id, name FROM server_configs WHERE status = 'active'")
    servers = cursor.fetchall()
    
    for server in servers:
        job_id = f"server_job_{server['id']}"
        scheduler.add_job(
            func=run_server_monitoring_check,
            trigger=IntervalTrigger(minutes=5),
            args=[server['id']],
            id=job_id,
            name=f"Monitor server: {server['name']}",
            replace_existing=True
        )
        print(f"Scheduled server monitoring job for '{server['name']}' every 5 minutes.")

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
    
    cursor.close()
    conn.close()

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

@app.route("/connections", methods=["GET", "POST"])
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
    
    # GET
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM prometheus_connections ORDER BY created_at DESC")
    conns = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("connections.html", connections=conns)

@app.route("/connections/<int:conn_id>", methods=["DELETE"])
def delete_connection(conn_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) AS total FROM alert_configs WHERE prometheus_id = %s", (conn_id,))
        if cursor.fetchone()['total'] > 0:
            return jsonify({"status": "error", "message": "Cannot delete connection while alert rules use it."}), 400

        cursor.execute("DELETE FROM prometheus_connections WHERE id = %s", (conn_id,))
        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({"status": "error", "message": "Connection not found."}), 404

        conn.commit()
        return jsonify({"status": "ok"})
    except Exception:
        conn.rollback()
        app.logger.exception("Failed to delete Prometheus connection %s", conn_id)
        return jsonify({"status": "error", "message": "Unable to delete the connection."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/alert-config", methods=["GET", "POST"])
def alert_config():
    if request.method == "POST":
        config_id = request.form.get("config_id")  # If editing
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
        
        try:
            if config_id:  # UPDATE
                cursor.execute("""
                    UPDATE alert_configs
                    SET name=%s, app_name=%s, prometheus_id=%s, query_string=%s, interval_minutes=%s,
                        warning_threshold=%s, critical_threshold=%s, msteams_webhook=%s,
                        payload_name=%s, payload_error=%s, payload_detail=%s, payload_action=%s, payload_grafana=%s
                    WHERE id=%s
                """, (data['name'], data['app_name'], data['prometheus_id'], data['query_string'],
                      data['interval_minutes'], data['warning_threshold'], data['critical_threshold'],
                      data['msteams_webhook'], data['payload_name'], data['payload_error'],
                      data['payload_detail'], data['payload_action'], data['payload_grafana'], config_id))
                
                if cursor.rowcount == 0:
                    conn.rollback()
                    flash("Alert config not found.", "error")
                else:
                    conn.commit()
                    load_jobs_from_db()
                    flash(f"Alert config '{data['name']}' updated successfully.", "success")
            else:  # INSERT
                cursor.execute("""
                    INSERT INTO alert_configs 
                    (name, app_name, prometheus_id, query_string, interval_minutes, warning_threshold, 
                     critical_threshold, msteams_webhook, payload_name, payload_error, payload_detail, 
                     payload_action, payload_grafana)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, tuple(data.values()))
                
                # Initialize alert state
                new_config_id = cursor.fetchone()['id']
                cursor.execute("INSERT INTO alert_states (alert_config_id) VALUES (%s)", (new_config_id,))
                conn.commit()
                
                load_jobs_from_db()
                flash(f"Alert config '{data['name']}' created successfully.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error saving alert config: {str(e)}", "error")
        finally:
            cursor.close()
            conn.close()
        
        return redirect(url_for("dashboard"))

    # GET
    config = None
    config_id = request.args.get('id')
    
    conn = get_db()
    cursor = conn.cursor()
    
    if config_id:
        cursor.execute("SELECT * FROM alert_configs WHERE id = %s", (config_id,))
        config = cursor.fetchone()
    
    cursor.execute("SELECT * FROM prometheus_connections")
    connections = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template("alert_config.html", connections=connections, config=config)

@app.route("/alert-config/<int:config_id>", methods=["DELETE"])
def delete_alert_config(config_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Child records must be removed first because they reference alert_configs.
        cursor.execute("DELETE FROM alert_logs WHERE alert_config_id = %s", (config_id,))
        cursor.execute("DELETE FROM alert_states WHERE alert_config_id = %s", (config_id,))
        cursor.execute("DELETE FROM alert_configs WHERE id = %s", (config_id,))

        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({"status": "error", "message": "Alert rule not found."}), 404

        conn.commit()
    except Exception:
        conn.rollback()
        app.logger.exception("Failed to delete alert rule %s", config_id)
        return jsonify({"status": "error", "message": "Unable to delete the alert rule."}), 500
    finally:
        cursor.close()
        conn.close()

    load_jobs_from_db()
    return jsonify({"status": "ok"})

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

@app.route("/trigger-server-monitoring/<int:server_id>", methods=["POST"])
def trigger_server_monitoring(server_id):
    """Manually trigger server monitoring check."""
    try:
        run_server_monitoring_check(server_id)
        return jsonify({"status": "ok", "message": "Server monitoring check triggered"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/test-server-monitoring/<int:server_id>", methods=["POST"])
def test_server_monitoring(server_id):
    """Test server monitoring queries."""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT sc.*, pc.url as prometheus_url
            FROM server_configs sc
            JOIN prometheus_connections pc ON sc.prometheus_id = pc.id
            WHERE sc.id = %s
        """, (server_id,))
        config = cursor.fetchone()
        
        if not config:
            return jsonify({"status": "error", "message": "Server config not found"}), 404
        
        results = {}
        
        # Test each query
        if config['cpu_query']:
            value, error = query_prometheus(config['prometheus_url'], config['cpu_query'])
            results['cpu'] = {'value': value, 'error': error}
        
        if config['memory_query']:
            value, error = query_prometheus(config['prometheus_url'], config['memory_query'])
            results['memory'] = {'value': value, 'error': error}
        
        if config['disk_query']:
            value, error = query_prometheus(config['prometheus_url'], config['disk_query'])
            results['disk'] = {'value': value, 'error': error}
        
        cursor.close()
        conn.close()
        
        return jsonify({"status": "ok", "results": results})
    
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({"status": "error", "message": str(e)}), 500

# --- Server Monitoring Routes ---
@app.route("/servers", methods=["GET"])
def servers():
    """Display list of monitored servers with current metrics."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT sc.*, p.name as prom_name
        FROM server_configs sc
        LEFT JOIN prometheus_connections p ON sc.prometheus_id = p.id
        ORDER BY sc.created_at DESC
    """)
    server_configs = cursor.fetchall()
    
    # Get latest metrics for each server
    server_metrics = {}
    for server in server_configs:
        cursor.execute("""
            SELECT metric_type, metric_value, current_state, created_at
            FROM server_metrics
            WHERE server_config_id = %s
            ORDER BY created_at DESC
            LIMIT 3
        """, (server['id'],))
        metrics = cursor.fetchall()
        server_metrics[server['id']] = {m['metric_type']: m for m in metrics}
    
    cursor.close()
    conn.close()
    
    return render_template("servers.html", servers=server_configs, metrics=server_metrics)

@app.route("/server-config", methods=["GET", "POST"])
def server_config():
    """Create or update server monitoring configuration."""
    if request.method == "POST":
        config_id = request.form.get("config_id")  # If editing
        data = {
            'name': request.form.get("name"),
            'target': request.form.get("target"),
            'prometheus_id': request.form.get("prometheus_id"),
            'cpu_query': request.form.get("cpu_query"),
            'memory_query': request.form.get("memory_query"),
            'disk_query': request.form.get("disk_query"),
            'cpu_warning_threshold': request.form.get("cpu_warning_threshold", 70, type=float),
            'cpu_critical_threshold': request.form.get("cpu_critical_threshold", 90, type=float),
            'memory_warning_threshold': request.form.get("memory_warning_threshold", 75, type=float),
            'memory_critical_threshold': request.form.get("memory_critical_threshold", 90, type=float),
            'disk_warning_threshold': request.form.get("disk_warning_threshold", 80, type=float),
            'disk_critical_threshold': request.form.get("disk_critical_threshold", 95, type=float),
            'msteams_webhook': request.form.get("msteams_webhook"),
            'payload_name': request.form.get("payload_name"),
            'payload_error': request.form.get("payload_error"),
            'payload_detail': request.form.get("payload_detail"),
            'payload_action': request.form.get("payload_action"),
            'payload_grafana': request.form.get("payload_grafana"),
        }
        
        if not all([data['name'], data['prometheus_id'], data['msteams_webhook']]):
            flash("Name, Prometheus connection, and Teams webhook are required.", "error")
            return redirect(url_for("server_config"))
        
        if not any([data['cpu_query'], data['memory_query'], data['disk_query']]):
            flash("At least one query (CPU, Memory, or Disk) is required.", "error")
            return redirect(url_for("server_config"))
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            if config_id:  # UPDATE
                cursor.execute("""
                    UPDATE server_configs
                    SET name=%s, target=%s, prometheus_id=%s, cpu_query=%s, memory_query=%s, disk_query=%s,
                        cpu_warning_threshold=%s, cpu_critical_threshold=%s,
                        memory_warning_threshold=%s, memory_critical_threshold=%s,
                        disk_warning_threshold=%s, disk_critical_threshold=%s,
                        msteams_webhook=%s, payload_name=%s, payload_error=%s, payload_detail=%s, 
                        payload_action=%s, payload_grafana=%s
                    WHERE id=%s
                """, (data['name'], data['target'], data['prometheus_id'], data['cpu_query'], data['memory_query'],
                      data['disk_query'], data['cpu_warning_threshold'], data['cpu_critical_threshold'],
                      data['memory_warning_threshold'], data['memory_critical_threshold'],
                      data['disk_warning_threshold'], data['disk_critical_threshold'],
                      data['msteams_webhook'], data['payload_name'], data['payload_error'], 
                      data['payload_detail'], data['payload_action'], data['payload_grafana'], config_id))
                
                if cursor.rowcount == 0:
                    conn.rollback()
                    flash("Server config not found.", "error")
                else:
                    conn.commit()
                    load_jobs_from_db()
                    flash(f"Server configuration '{data['name']}' updated successfully.", "success")
            else:  # INSERT
                cursor.execute("""
                    INSERT INTO server_configs 
                    (name, target, prometheus_id, cpu_query, memory_query, disk_query,
                     cpu_warning_threshold, cpu_critical_threshold,
                     memory_warning_threshold, memory_critical_threshold,
                     disk_warning_threshold, disk_critical_threshold,
                     msteams_webhook, payload_name, payload_error, payload_detail, payload_action, payload_grafana)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, tuple(data.values()))
                
                config_id = cursor.fetchone()['id']
                conn.commit()
                
                # Reload scheduler
                load_jobs_from_db()
                
                flash(f"Server configuration '{data['name']}' created successfully.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error saving server config: {str(e)}", "error")
        finally:
            cursor.close()
            conn.close()
        
        return redirect(url_for("servers"))
    
    # GET
    config = None
    config_id = request.args.get('id')
    
    conn = get_db()
    cursor = conn.cursor()
    
    if config_id:
        cursor.execute("SELECT * FROM server_configs WHERE id = %s", (config_id,))
        config = cursor.fetchone()
    
    cursor.execute("SELECT * FROM prometheus_connections")
    connections = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("server_config.html", connections=connections, config=config)

@app.route("/api/servers", methods=["GET"])
def get_servers_api():
    """API endpoint to fetch all servers for dropdown selection."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM server_configs ORDER BY name ASC")
    servers = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([{"id": s['id'], "name": s['name']} for s in servers])

@app.route("/api/prometheus-targets", methods=["GET"])
def get_prometheus_targets():
    """API endpoint to fetch targets from Prometheus."""
    prometheus_id = request.args.get('prometheus_id')
    
    if not prometheus_id:
        return jsonify({"status": "error", "message": "prometheus_id required"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT url FROM prometheus_connections WHERE id = %s", (prometheus_id,))
        result = cursor.fetchone()
        
        if not result:
            cursor.close()
            conn.close()
            return jsonify({"status": "error", "message": "Prometheus connection not found"}), 404
        
        prometheus_url = result['url']
        
        # Fetch targets from Prometheus
        targets_url = f"{prometheus_url.rstrip('/')}/api/v1/targets"
        response = requests.get(targets_url, verify=False, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                targets_data = data.get('data', {})
                active_targets = targets_data.get('activeTargets', [])
                
                # Extract unique target labels
                targets = []
                seen = set()
                
                for target in active_targets:
                    labels = target.get('labels', {})
                    job = labels.get('job', '')
                    instance = labels.get('instance', '')
                    
                    if instance and instance not in seen:
                        targets.append({
                            "instance": instance,
                            "job": job,
                            "labels": labels
                        })
                        seen.add(instance)
                
                cursor.close()
                conn.close()
                return jsonify({"status": "success", "targets": targets})
        
        cursor.close()
        conn.close()
        return jsonify({"status": "error", "message": "Failed to fetch targets from Prometheus"}), 500
    
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/server-config/<int:config_id>", methods=["DELETE"])
def delete_server_config(config_id):
    """Delete server monitoring configuration."""
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Delete related metrics
        cursor.execute("DELETE FROM server_metrics WHERE server_config_id = %s", (config_id,))
        cursor.execute("DELETE FROM server_configs WHERE id = %s", (config_id,))

        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({"status": "error", "message": "Server config not found."}), 404

        conn.commit()
        
        # Reload scheduler
        load_jobs_from_db()
        
        return jsonify({"status": "ok"})
    except Exception as e:
        conn.rollback()
        app.logger.exception("Failed to delete server config %s", config_id)
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/api/server-metrics/<int:config_id>")
def api_server_metrics(config_id):
    """Get latest metrics for a server (JSON API)."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT metric_type, metric_value, current_state, created_at
        FROM server_metrics
        WHERE server_config_id = %s
        ORDER BY created_at DESC
        LIMIT 10
    """, (config_id,))
    metrics = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return jsonify({
        "status": "ok",
        "metrics": [dict(m) for m in metrics]
    })

if __name__ == "__main__":
    init_db()
    migrate_add_target_column()
    migrate_add_payload_columns()
    load_jobs_from_db()
    scheduler.start()
    app.run(host="0.0.0.0", port=5000, debug=False)
