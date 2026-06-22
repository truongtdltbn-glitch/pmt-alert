import datetime
import requests
import urllib3
import logging
import json
from database import get_db, init_db

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("scheduler")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(sh)

def format_payload_field(template, variables):
    """Format template string with variable values, tolerating missing keys safely."""
    if not template:
        return ""
    try:
        return template.format(**variables)
    except KeyError as e:
        logger.warning(f"Key missing during format: {e}")
        return template
    except Exception as e:
        logger.error(f"Error formatting field: {e}")
        return template

def query_prometheus(prometheus_url, query_string):
    """
    Query Prometheus using instant query.
    Returns (result_count, error_msg).
    """
    url = f"{prometheus_url.rstrip('/')}/api/v1/query"
    params = {'query': query_string}
    
    logger.info(f"Querying Prometheus: {url} | Query: {query_string}")
    
    try:
        response = requests.get(url, params=params, verify=False, timeout=20)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                results = data.get('data', {}).get('result', [])
                # Sum all values from results
                total_value = 0
                for result in results:
                    try:
                        value = float(result['value'][1])
                        total_value += value
                    except (KeyError, ValueError, TypeError):
                        pass
                logger.info(f"Prometheus query result: {total_value}")
                return total_value, None
            else:
                err_msg = data.get('error', 'Unknown error')
                logger.error(f"Prometheus error: {err_msg}")
                return 0, err_msg
        else:
            err_msg = f"HTTP {response.status_code}: {response.text[:200]}"
            logger.error(f"Prometheus Query Failed: {err_msg}")
            return 0, err_msg
    except Exception as e:
        err_msg = str(e)
        logger.error(f"Prometheus connection error: {err_msg}")
        return 0, err_msg

def send_teams_alert(webhook_url, payload):
    """Send alert to Microsoft Teams webhook."""
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(webhook_url, json=payload, headers=headers, timeout=15)
        if response.status_code == 200:
            logger.info(f"Teams alert sent successfully to {webhook_url}")
            return True
        else:
            logger.error(f"Teams webhook failed: HTTP {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"Failed to send Teams alert: {str(e)}")
        return False

def run_alert_check(alert_config_id):
    """Main alert checking logic."""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Get alert config
        cursor.execute("""
            SELECT ac.*, pc.url as prometheus_url
            FROM alert_configs ac
            JOIN prometheus_connections pc ON ac.prometheus_id = pc.id
            WHERE ac.id = %s
        """, (alert_config_id,))
        config = cursor.fetchone()
        
        if not config:
            logger.error(f"Alert config {alert_config_id} not found")
            return
        
        # Initialize alert state if doesn't exist
        cursor.execute("SELECT * FROM alert_states WHERE alert_config_id = %s", (alert_config_id,))
        state = cursor.fetchone()
        if not state:
            cursor.execute("""
                INSERT INTO alert_states (alert_config_id, current_state)
                VALUES (%s, 'ok')
            """, (alert_config_id,))
            conn.commit()
            state = cursor.fetchone()
        
        # Query Prometheus
        query_value, query_error = query_prometheus(
            config['prometheus_url'],
            config['query_string']
        )
        
        # Determine alert state
        new_state = 'ok'
        if query_error:
            new_state = 'error'
        elif query_value >= config['critical_threshold']:
            new_state = 'critical'
        elif query_value >= config['warning_threshold']:
            new_state = 'warning'
        
        # Prepare log variables
        variables = {
            'alert_name': config['name'],
            'app_name': config['app_name'] or 'Unknown',
            'query': config['query_string'],
            'value': f"{query_value:.2f}",
            'warning_threshold': config['warning_threshold'],
            'critical_threshold': config['critical_threshold'],
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        # Log this check
        cursor.execute("""
            INSERT INTO alert_logs 
            (alert_config_id, alert_state, query_result_count, threshold, message)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            alert_config_id,
            new_state,
            query_value,
            config['critical_threshold'] if new_state == 'critical' else config['warning_threshold'],
            query_error or f"Value: {query_value}"
        ))
        
        # Send alert if state changed or is critical/warning
        should_send_alert = False
        if new_state != state['current_state']:
            should_send_alert = True
        elif new_state in ['critical', 'warning']:
            should_send_alert = True
        
        if should_send_alert:
            payload = {
                "type": new_state,
                "name": format_payload_field(config['payload_name'], variables),
                "error": format_payload_field(config['payload_error'], variables),
                "detail": [format_payload_field(config['payload_detail'], variables)],
                "action": format_payload_field(config['payload_action'], variables),
                "grafana": format_payload_field(config['payload_grafana'], variables)
            }
            
            send_teams_alert(config['msteams_webhook'], payload)
            
            # Update state
            cursor.execute("""
                UPDATE alert_states 
                SET current_state = %s, last_triggered_at = CURRENT_TIMESTAMP, last_triggered_count = last_triggered_count + 1
                WHERE alert_config_id = %s
            """, (new_state, alert_config_id))
        
        # Update last checked time
        cursor.execute("""
            UPDATE alert_states 
            SET last_checked_at = CURRENT_TIMESTAMP
            WHERE alert_config_id = %s
        """, (alert_config_id,))
        
        conn.commit()
        logger.info(f"Alert check completed: {config['name']} → {new_state}")
        
    except Exception as e:
        logger.error(f"Error in alert check: {str(e)}")
    finally:
        conn.close()

def run_server_monitoring_check(server_config_id):
    """Check server metrics and send alerts if thresholds exceeded."""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Get server config
        cursor.execute("""
            SELECT sc.*, pc.url as prometheus_url
            FROM server_configs sc
            JOIN prometheus_connections pc ON sc.prometheus_id = pc.id
            WHERE sc.id = %s
        """, (server_config_id,))
        config = cursor.fetchone()
        
        if not config:
            logger.error(f"Server config {server_config_id} not found")
            return
        
        # Query metrics
        metrics = {}
        metric_types = {
            'cpu': (config['cpu_query'], config['cpu_warning_threshold'], config['cpu_critical_threshold']),
            'memory': (config['memory_query'], config['memory_warning_threshold'], config['memory_critical_threshold']),
            'disk': (config['disk_query'], config['disk_warning_threshold'], config['disk_critical_threshold'])
        }
        
        alerts_to_send = []
        
        for metric_type, (query, warning_threshold, critical_threshold) in metric_types.items():
            if not query:
                continue
            
            metric_value, query_error = query_prometheus(config['prometheus_url'], query)
            
            # Determine state
            state = 'ok'
            if query_error:
                state = 'error'
            elif metric_value >= critical_threshold:
                state = 'critical'
            elif metric_value >= warning_threshold:
                state = 'warning'
            
            # Store metric
            cursor.execute("""
                INSERT INTO server_metrics 
                (server_config_id, metric_type, metric_value, current_state)
                VALUES (%s, %s, %s, %s)
            """, (server_config_id, metric_type, metric_value, state))
            
            metrics[metric_type] = {
                'value': metric_value,
                'state': state,
                'warning': warning_threshold,
                'critical': critical_threshold
            }
            
            # Queue alert if needed
            if state in ['critical', 'warning']:
                alerts_to_send.append({
                    'type': metric_type,
                    'state': state,
                    'value': metric_value,
                    'threshold': critical_threshold if state == 'critical' else warning_threshold,
                    'warning': warning_threshold,
                    'critical': critical_threshold
                })
        
        conn.commit()
        
        # Send alerts if any
        if alerts_to_send:
            for alert in alerts_to_send:
                # Prepare variables for payload formatting
                variables = {
                    'alert_name': config['name'],
                    'app_name': config['name'],
                    'query': alert['type'].upper(),
                    'value': f"{alert['value']:.2f}%",
                    'warning_threshold': f"{alert['warning']:.2f}%",
                    'critical_threshold': f"{alert['critical']:.2f}%",
                    'timestamp': datetime.datetime.now().isoformat(),
                    'target': config.get('target', 'Unknown'),
                    'metric_type': alert['type']
                }
                
                # Build Teams payload from templates
                payload = {
                    "@type": "MessageCard",
                    "@context": "https://schema.org/extensions",
                    "summary": format_payload_field(config.get('payload_name', 'Server Alert: {alert_name}'), variables),
                    "themeColor": "FF0000" if alert['state'] == 'critical' else "FFA500",
                    "sections": [
                        {
                            "activityTitle": format_payload_field(config.get('payload_name', 'Server Alert: {alert_name}'), variables),
                            "facts": [
                                {"name": "Server", "value": config['name']},
                                {"name": "Target", "value": config.get('target', 'N/A')},
                                {"name": "Metric", "value": alert['type'].upper()},
                                {"name": "Status", "value": alert['state'].upper()},
                                {"name": "Current Value", "value": f"{alert['value']:.2f}%"},
                                {"name": "Threshold", "value": f"{alert['threshold']:.2f}%"},
                                {"name": "Timestamp", "value": datetime.datetime.now().isoformat()},
                                {"name": "Error", "value": format_payload_field(config.get('payload_error', 'N/A'), variables)},
                                {"name": "Detail", "value": format_payload_field(config.get('payload_detail', 'Check server metrics'), variables)},
                            ],
                            "markdown": True
                        }
                    ],
                    "potentialAction": [
                        {
                            "@type": "OpenUri",
                            "name": "View Details",
                            "targets": [
                                {
                                    "os": "default",
                                    "uri": format_payload_field(config.get('payload_grafana', '#'), variables)
                                }
                            ]
                        }
                    ]
                }
                
                # Add action if provided
                if config.get('payload_action'):
                    payload["potentialAction"][0]["name"] = format_payload_field(config.get('payload_action', 'View Details'), variables)
                
                send_teams_alert(config['msteams_webhook'], payload)
            
            logger.info(f"Server monitoring alerts sent for {config['name']}: {[a['type'] for a in alerts_to_send]}")
        
        logger.info(f"Server monitoring completed: {config['name']} → CPU: {metrics.get('cpu', {}).get('value', 'N/A')}%, Memory: {metrics.get('memory', {}).get('value', 'N/A')}%, Disk: {metrics.get('disk', {}).get('value', 'N/A')}%")
        
    except Exception as e:
        logger.error(f"Error in server monitoring: {str(e)}")
    finally:
        conn.close()
