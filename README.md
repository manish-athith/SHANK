<img width="1795" height="918" alt="image" src="https://github.com/user-attachments/assets/c716b991-ef6d-461b-a596-813bb7baa1a4" /># SHANK

## Real-Time AI-Powered Phishing Detection & Cybersecurity Intelligence Platform

SHANK is a Dockerized cybersecurity platform for real-time phishing URL detection, threat scoring, forensic storage, and SOC-style alert monitoring.

It ingests URL/security events through APIs and Kafka, extracts runtime-safe URL features, scores threats using a calibrated XGBoost classifier and Isolation Forest anomaly detector, stores events in PostgreSQL, streams alerts through WebSockets, and displays results in a React dashboard.

> SHANK is built as a serious local-deployable cybersecurity project, not a toy demo.  
> It is suitable for portfolio, resume, final-year project, and research-style extension.

---

## Screenshots

### Dashboard Overview

<img width="1883" height="913" alt="image" src="https://github.com/user-attachments/assets/2856b43d-1cbd-43d0-8162-b039b09a8681" />


```text
docs/screenshots/dashboard-overview.png
```

### URL Threat Analysis

<img width="1753" height="721" alt="image" src="https://github.com/user-attachments/assets/f66b6885-5c10-47e8-a4cc-49e3e73375f7" />

<img width="1795" height="918" alt="image" src="https://github.com/user-attachments/assets/60e4ca51-0a06-4fd3-b34c-faae1bafcd67" />



```text
docs/screenshots/url-threat-analysis.png
```

### Alerts & Monitoring

<img width="1704" height="891" alt="image" src="https://github.com/user-attachments/assets/52f70720-6714-4de2-94ba-9218003340bd" />


```text
docs/screenshots/alerts-monitoring.png
```

---

## What SHANK Does

SHANK helps detect and monitor suspicious URLs in a local security operations workflow.

It can:

- Accept URL submissions through REST APIs.
- Consume security events through Kafka.
- Extract URL-based features without visiting unsafe websites.
- Predict phishing risk using machine learning.
- Detect unusual patterns with anomaly detection.
- Store predictions, events, and alerts in PostgreSQL.
- Stream live alerts to the dashboard through WebSockets.
- Provide authenticated dashboard access using JWT tokens.
- Expose API documentation through FastAPI Swagger UI.
- Run locally through Docker Compose.

---

## Why This Project Matters

Phishing remains one of the most common attack paths in cybersecurity. SHANK demonstrates how a real-world detection platform can combine backend engineering, machine learning, streaming systems, authentication, databases, and frontend monitoring into one deployable system.

This project is designed to show practical engineering ability across:

- Cybersecurity threat detection
- Machine learning model integration
- Backend API development
- Streaming event pipelines
- Database-backed forensic storage
- Dockerized deployment
- React dashboard development
- Authentication and protected APIs
- Testable, extensible system design

---

## Tech Stack

| Layer | Technology |
| --- | --- |
| Frontend | React, Vite, Tailwind CSS, Recharts |
| Backend API | FastAPI, Python |
| Authentication | JWT |
| Machine Learning | XGBoost, Isolation Forest, scikit-learn |
| Database | PostgreSQL |
| Streaming | Apache Kafka |
| Monitoring | Prometheus |
| Deployment | Docker Compose |
| Testing | pytest, frontend production build |

---

## System Architecture

```text
User / API Client
      |
      v
React Dashboard  <---- WebSocket Alerts ---- FastAPI Backend
      |                                      |
      |                                      v
      |                              PostgreSQL Storage
      |                                      ^
      |                                      |
      v                                      |
REST API Requests                    Stream Processor
                                             ^
                                             |
                                      Kafka Event Topics
                                             ^
                                             |
                                  Sample / External Events
```

High-level flow:

1. A user logs in to the dashboard and receives a JWT.
2. URLs or security events are submitted through the API or Kafka.
3. SHANK extracts safe URL features.
4. The ML pipeline scores phishing probability and anomaly risk.
5. Results are stored in PostgreSQL.
6. High-risk results generate alerts.
7. Alerts are streamed live to authenticated dashboard users.

---

## Key Features

### Real-Time Phishing Detection

SHANK analyzes submitted URLs and returns a risk score, severity level, confidence score, and phishing probability.

### Machine Learning Scoring

The detection layer combines:

- XGBoost classifier for phishing prediction
- Isolation Forest for anomaly detection
- Runtime-safe URL feature extraction
- Calibration guardrails for more stable local testing

### SOC-Style Dashboard

The React dashboard provides:

- Live connection state
- Event and alert counts
- Severity metrics
- Recent alert table
- URL scan form
- Visual severity trend chart
- Authenticated access
- Logout support

### Kafka Event Pipeline

SHANK can consume raw security events from Kafka, process them, persist results, and emit alerts for downstream consumers.

### Forensic Storage

PostgreSQL stores events, predictions, and alerts so detections can be reviewed later instead of disappearing after runtime.

### Dockerized Local Deployment

The project is designed to run locally with Docker Compose, making it easier to demonstrate and reproduce.

---

## Quick Start

### 1. Clone the Repository

```powershell
git clone https://github.com/manish-athith/SHANK.git
cd SHANK
```

### 2. Create Environment File

```powershell
copy .env.example .env
```

Before using SHANK outside local development, update secrets such as:

- `SECRET_KEY`
- `SHANK_ADMIN_PASSWORD`
- Database credentials
- Any production deployment credentials

### 3. Start the Platform

```powershell
docker compose up --build
```

### 4. Seed the Local Admin User

```powershell
docker compose exec backend python /app/scripts/seed_admin.py
```

### 5. Open the Services

| Service | URL |
| --- | --- |
| Dashboard | http://localhost:5173 |
| API Docs | http://localhost:8000/docs |
| Prometheus | http://localhost:9090 |

Default local admin:

```text
Email: admin@shank.local
Password: ChangeMe123!
```

> Change the default password before exposing SHANK beyond your workstation.

---

## Using the Dashboard

1. Open `http://localhost:5173`.
2. Log in with the seeded admin account.
3. Submit a suspicious or benign URL in the analysis form.
4. Review risk score, severity, confidence, and phishing probability.
5. Watch the alert table and metrics update as new events are processed.

---

## API Smoke Test

You can test the protected API from PowerShell:

```powershell
$login = Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/auth/login" -ContentType "application/x-www-form-urlencoded" -Body "username=admin@shank.local&password=ChangeMe123!"
$headers = @{ Authorization = "Bearer $($login.access_token)" }
$body = @{ url = "http://secure-login-paypa1.example.info/update-billing"; source = "powershell" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/predict-url" -Headers $headers -ContentType "application/json" -Body $body
```

---

## Kafka Event Demo

Produce sample live events:

```powershell
docker compose exec backend python /app/scripts/produce_sample_events.py
```

The stream processor consumes raw events, scores them, stores predictions, creates alerts above the configured threshold, and sends live alerts to authenticated dashboard clients.

---

## Training Models

SHANK can run with deterministic fallback behavior if trained model files are not present. For stronger local results, train model artifacts with a larger phishing URL dataset.

Local training example:

```powershell
$env:PYTHONPATH="$PWD\backend;$PWD"
.\scripts\train_models.ps1
```

PhiUSIIL training example:

```powershell
py -3.11 -m ml.training.train --dataset datasets/phiusiil_phishing_urls.csv --model-dir ml/models --metrics ml/models/metrics.json
```

Docker training example:

```powershell
docker compose exec backend python -m ml.training.train --dataset datasets/phiusiil_phishing_urls.csv --model-dir ml/models --metrics ml/models/metrics.json
docker compose restart backend stream-processor
```

After training, review:

```text
ml/models/metrics.json
```

This file includes model metrics, confusion matrix details, dataset metadata, feature information, and quality warnings.

> Model metrics are useful for local validation, but they are not a production security guarantee.

---

## Pretrained Model Artifacts

Pretrained SHANK model artifacts are available in the GitHub release:

```text
https://github.com/manish-athith/SHANK/releases/tag/models-phiusiil-v1
```

Download these files into `ml/models/` if you want to run SHANK without retraining:

- `phishing_xgb.joblib`
- `anomaly_iforest.joblib`
- `metrics.json`
- `manual_validation_summary.json`

These artifacts are intended for local demo, portfolio, and research validation.

---

## API Endpoints

Authenticate first:

```text
POST /api/v1/auth/login
```

Protected and utility endpoints include:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/detect` | Submit detection request |
| `POST` | `/api/v1/predict-url` | Score a URL |
| `POST` | `/api/v1/threat-check` | Run a threat check |
| `GET` | `/api/v1/alerts` | List alerts |
| `GET` | `/api/v1/alerts/live` | Live alert WebSocket |
| `GET` | `/api/v1/stats` | Dashboard statistics |
| `GET` | `/api/v1/health` | Service health |

---

## Testing

Backend tests:

```powershell
py -3.11 -m pytest -q
```

Frontend production build:

```powershell
npm --prefix frontend run build
```

---

## Project Structure

```text
SHANK/
├── backend/        FastAPI application and backend services
├── frontend/       React dashboard
├── ml/             ML training and model artifacts
├── kafka/          Kafka-related configuration
├── monitoring/     Prometheus monitoring configuration
├── scripts/        Utility, training, and demo scripts
├── datasets/       Local datasets and training inputs
├── docs/           Documentation and screenshot placeholders
└── docker-compose.yml
```

---

## Security Notes

- SHANK uses JWT authentication for protected dashboard and API access.
- Do not expose default credentials publicly.
- Rotate `SECRET_KEY` before any non-local deployment.
- Treat local model outputs as decision-support signals, not final security verdicts.
- Do not submit sensitive real user data to a local demo environment unless you understand the storage and retention behavior.

---

## Resume Highlights

SHANK demonstrates:

- End-to-end cybersecurity product engineering
- ML-backed phishing risk scoring
- Secure authenticated API design
- Event-driven architecture with Kafka
- Live dashboard updates through WebSockets
- PostgreSQL-backed forensic storage
- Dockerized multi-service deployment
- Practical testing and validation workflow

---

## Future Improvements

Potential extensions:

- Add richer threat intelligence feed ingestion
- Add analyst workflow actions for alerts
- Add role-based access control
- Add downloadable reports
- Add model drift monitoring
- Add email and domain reputation enrichment
- Add CI/CD deployment workflow

---

## License

Add your project license here.
