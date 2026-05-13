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

The included `datasets/phishing_urls_seed.csv` file has only 20 rows and is smoke-test-only. For meaningful local metrics, train with the PhiUSIIL URL dataset:

```powershell
py -3.11 -m ml.training.train --dataset datasets/phiusiil_phishing_urls.csv --model-dir ml/models --metrics ml/models/metrics.json
```

Or inside Docker:

```powershell
docker compose exec backend python -m ml.training.train --dataset datasets/phiusiil_phishing_urls.csv --model-dir ml/models --metrics ml/models/metrics.json
docker compose restart backend stream-processor
```

PhiUSIIL uses `URL` as the input URL column and `label` as the source label. SHANK converts PhiUSIIL labels so source `label = 0` becomes phishing target `1`, and source `label = 1` becomes benign target `0`. This preserves `/api/v1/predict-url` semantics: higher `phishing_probability` means higher phishing risk. Training intentionally ignores PhiUSIIL precomputed feature columns and regenerates SHANK runtime features from each URL.

After training, inspect `ml/models/metrics.json` for accuracy, precision, recall, F1, ROC-AUC, confusion matrix, false positives, false negatives, the feature list, dataset metadata, and any quality warnings. Treat unusually perfect metrics as a prompt to review data leakage or duplicate URLs, not as an automatic production claim.

Run the manual validation sets after training:

```powershell
py -3.11 scripts/evaluate_manual_urls.py
```

This writes:

- `ml/models/manual_validation_results.csv` and `manual_validation_summary.json` for the calibration guardrail set.
- `ml/models/manual_holdout_results.csv` and `manual_holdout_summary.json` for the independent holdout set.

Training metrics measure the PhiUSIIL train/test split. The calibration guardrail helps reduce obvious real-world URL false positives. The independent holdout is the closest local regression check for real-world benign URLs and synthetic impersonation URLs that were not used for calibration. SHANK is still URL-feature-only; these artifacts are demo/research artifacts and are not production proof.

The dashboard renders backend timestamps in browser-local time. Older backend timestamps that omit a timezone are treated as UTC before display.

You can still download external feeds for experimentation:

```powershell
$env:PYTHONPATH="$PWD\backend;$PWD"
python scripts/download_feeds.py
python -m ml.training.train --dataset datasets/phishing_urls_training.csv --model-dir ml/models --metrics ml/models/metrics.json
python scripts/ingest_threat_feeds.py
```

## Pretrained Model Artifacts

Pretrained SHANK model artifacts are available in the GitHub release:

https://github.com/manish-athith/SHANK/releases/tag/models-phiusiil-v1

Download these files into `ml/models/` if you want to run SHANK without retraining:

- `phishing_xgb.joblib`
- `anomaly_iforest.joblib`
- `metrics.json`
- `manual_validation_summary.json`

These artifacts are trained on runtime-compatible URL features using the PhiUSIIL dataset and calibrated with a small manual validation guardrail set. They are intended for local demo and research validation, not production security guarantees.

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
