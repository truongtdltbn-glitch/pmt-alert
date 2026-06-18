# Prometheus Alert Dashboard (pmt-alert)

Prometheus alert monitoring system với Flask web UI, tương tự như `elk-alert` nhưng dùng **Prometheus** thay vì ELK.

## Tính năng

✅ Query dữ liệu từ Prometheus endpoints  
✅ Cấu hình alert rules với PromQL  
✅ Gửi cảnh báo tự động qua Microsoft Teams Webhooks  
✅ Dashboard UI quản lý alerts  
✅ Lịch sử cảnh báo và logs  
✅ Hỗ trợ multiple Prometheus servers  

## Cấu trúc thư mục

```
pmt-alert/
├── app.py                 # Flask app & routes
├── database.py            # SQLite database
├── scheduler.py           # Alert checking logic
├── requirements.txt       # Python dependencies
├── Dockerfile             # Docker container
├── docker-compose.yml     # Docker Compose
├── templates/             # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── connections.html
│   ├── alert_config.html
│   ├── alerts.html
│   └── logs.html
└── pmt_alert.db          # SQLite database file
```

## Installation

### Local Development

```bash
# Clone repository
cd d:\soucecode\github\pmt-alert

# Install dependencies
pip install -r requirements.txt

# Initialize database
python -c "from database import init_db; init_db()"

# Run app
python app.py
```

Truy cập: `http://localhost:5000`

Default credentials:
- Username: `admin`
- Password: `PGBank@2026devops`

### Docker

```bash
# Build & start
docker-compose up -d

# View logs
docker-compose logs -f pmt-alert
```

## Usage

### 1. Add Prometheus Connection

Vào **Connections** tab, thêm Prometheus endpoints:

```
Name: Prometheus DC
URL: https://prometheus.pgbank.com.vn/api/v1/query

Name: Prometheus DR  
URL: https://prometheus-dr.pgbank.com.vn/api/v1/query
```

### 2. Create Alert Rule

Vào **Create Alert** tab, tạo rule mới:

```
Name: High CPU Usage
App Name: System Monitoring
Prometheus: Prometheus DC
PromQL Query: node_cpu_seconds_total{mode="user"} > 100
Interval: 5 minutes
Warning Threshold: 1
Critical Threshold: 5
Teams Webhook: https://outlook.webhook.office.com/...
```

Template variables khả dụng:
- `{alert_name}` - Alert name
- `{app_name}` - Application name
- `{query}` - PromQL query
- `{value}` - Query result value
- `{warning_threshold}` - Warning threshold
- `{critical_threshold}` - Critical threshold
- `{timestamp}` - Current timestamp

### 3. View Alerts

Vào **Logs** tab để xem lịch sử cảnh báo.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard |
| GET | `/connections` | List Prometheus connections |
| POST | `/connections` | Add connection |
| DELETE | `/connections` | Delete connection |
| GET | `/alert-config` | Alert config page |
| POST | `/alert-config` | Create alert rule |
| DELETE | `/alert-config` | Delete rule |
| GET | `/alerts` | Alert history |
| GET | `/logs/<id>` | Rule logs |
| POST | `/test-prometheus` | Test Prometheus query |

## Example PromQL Queries

```promql
# High CPU usage
rate(node_cpu_seconds_total{mode="user"}[5m]) > 0.8

# Memory usage
(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 > 80

# Disk usage
(1 - node_filesystem_free_bytes / node_filesystem_size_bytes) * 100 > 85

# Service down
count(up == 0) > 0

# High error rate
rate(http_requests_total{status=~"5.."}[5m]) > 0.1
```

## Environment Variables

```bash
export DB_PATH=/opt/pmt-alert/pmt_alert.db
export FLASK_ENV=production
export FLASK_DEBUG=0
```

## Database Schema

### prometheus_connections
- id (PK)
- name
- url
- created_at

### alert_configs
- id (PK)
- name
- app_name
- prometheus_id (FK)
- query_string
- interval_minutes
- warning_threshold
- critical_threshold
- msteams_webhook
- payload_* (templates)
- status
- created_at

### alert_states
- id (PK)
- alert_config_id (FK)
- current_state
- last_triggered_count
- last_checked_at
- last_triggered_at

### alert_logs
- id (PK)
- alert_config_id (FK)
- alert_state
- query_result_count
- threshold
- message
- created_at

## Teams Webhook Integration

Để tạo Teams webhook:

1. Vào Microsoft Teams Channel
2. Clic "..." → "Connectors"
3. Search "Incoming Webhook"
4. Configure & Copy URL
5. Paste URL vào Alert Config

## Troubleshooting

**"Cannot connect to Prometheus"**
- Kiểm tra Prometheus URL có đúng không
- Kiểm tra SSL certificate (disable verify nếu self-signed)

**"Alert không trigger"**
- Check scheduler logs: `tail -f logs/*.log`
- Test query: POST `/test-prometheus` với URL & query

**Database locked**
- Đóng tất cả Flask instances
- Xóa `.db-wal`, `.db-shm` files
- Restart app

## Production Deployment

### Systemd Service

```ini
[Unit]
Description=Prometheus Alert System
After=network.target

[Service]
Type=simple
User=alertsvc
WorkingDirectory=/opt/pmt-alert
ExecStart=/usr/bin/python3 /opt/pmt-alert/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Nginx Reverse Proxy

```nginx
server {
    listen 443 ssl http2;
    server_name pmt-alert.pgbank.com.vn;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Support

Liên hệ DevOps team để được hỗ trợ.
