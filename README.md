# SHANK

Real-time AI-powered phishing detection and cybersecurity intelligence platform.

SHANK ingests security events through Kafka and API endpoints, extracts URL/email indicators, scores events with an XGBoost phishing classifier plus Isolation Forest anomaly model, stores forensic records in PostgreSQL, emits alerts through WebSockets, and displays SOC operations views in React.

## Quick Start

```powershell
copy .env.example .env
docker compose up --build
docker compose exec backend python /app/scripts/seed_admin.py
```

Open:

- API docs: http://localhost:8000/docs
- Dashboard: http://localhost:5173
- Prometheus: http://localhost:9090

Default local admin created by the seed script:

- Email: `admin@shank.local`
- Password: `ChangeMe123!`

Change `SECRET_KEY`, `SHANK_ADMIN_PASSWORD`, and any production credentials before exposing SHANK outside your workstation.

## Smoke Test

```powershell
$login = Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/auth/login" -ContentType "application/x-www-form-urlencoded" -Body "username=admin@shank.local&password=ChangeMe123!"
$headers = @{ Authorization = "Bearer $($login.access_token)" }
$body = @{ url = "http://secure-login-paypa1.example.info/update-billing"; source = "powershell" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/predict-url" -Headers $headers -ContentType "application/json" -Body $body
```

Produce live Kafka events:

```powershell
docker compose exec backend python /app/scripts/produce_sample_events.py
```

The stream processor consumes `shank.raw.events`, writes predictions, creates alerts above threshold, publishes alert events to `shank.alerts`, and the backend fanout consumer pushes those alerts to authenticated dashboard WebSocket clients.

## Train Models

The app runs with a deterministic fallback if model files are absent. To create local model files:

```powershell
$env:PYTHONPATH="$PWD\backend;$PWD"
.\scripts\train_models.ps1
```

Or inside Docker:

```powershell
docker compose exec backend python -m ml.training.train --dataset datasets/phishing_urls_seed.csv --model-dir ml/models --metrics ml/models/metrics.json
docker compose restart backend stream-processor
```

The included 20-row seed dataset is for smoke testing only. Download real feeds before claiming stronger metrics:

```powershell
$env:PYTHONPATH="$PWD\backend;$PWD"
python scripts/download_feeds.py
python -m ml.training.train --dataset datasets/phishing_urls_training.csv --model-dir ml/models --metrics ml/models/metrics.json
python scripts/ingest_threat_feeds.py
```

## API

Authenticate with `/api/v1/auth/login`, then call:

- `POST /api/v1/detect`
- `POST /api/v1/predict-url`
- `POST /api/v1/threat-check`
- `GET /api/v1/alerts`
- `GET /api/v1/alerts/live`
- `GET /api/v1/stats`
- `GET /api/v1/health`

## Tests

```powershell
$env:PYTHONPATH="$PWD\backend;$PWD"
pytest
npm --prefix frontend run build
```
