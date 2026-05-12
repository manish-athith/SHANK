# Deployment Guide

## Local Docker Compose

```powershell
copy .env.example .env
docker compose up --build
docker compose exec backend python /app/scripts/seed_admin.py
```

Smoke-test the API:

```powershell
$login = Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/auth/login" -ContentType "application/x-www-form-urlencoded" -Body "username=admin@shank.local&password=ChangeMe123!"
$headers = @{ Authorization = "Bearer $($login.access_token)" }
$body = @{ url = "http://secure-login-paypa1.example.info/update-billing"; source = "powershell" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/predict-url" -Headers $headers -ContentType "application/json" -Body $body
docker compose exec backend python /app/scripts/produce_sample_events.py
```

Train seed models inside Docker:

```powershell
docker compose exec backend python -m ml.training.train --dataset datasets/phishing_urls_seed.csv --model-dir ml/models --metrics ml/models/metrics.json
docker compose restart backend stream-processor
```

The seed dataset is only for smoke testing. For real metrics, download feeds and train on `datasets/phishing_urls_training.csv` before evaluating model quality.

## Production Notes

- Replace `SECRET_KEY` with a generated secret.
- Set `SHANK_ADMIN_PASSWORD` before seeding, or rotate the default admin password immediately.
- Configure `VIRUSTOTAL_API_KEY` and `SLACK_WEBHOOK_URL` only through secrets.
- Use managed PostgreSQL with daily backups and point-in-time recovery.
- Use a multi-broker Kafka cluster with replication factor 3.
- Terminate TLS at a reverse proxy or ingress controller.
- Configure your domain, DNS, and TLS certificates before internet exposure.
- Restrict CORS origins to the deployed dashboard domain.
- Rotate admin credentials immediately after bootstrapping.
- Send container logs to SIEM or ELK/OpenSearch.
- Tune `RISK_ALERT_THRESHOLD` after observing model precision/recall against local traffic.

## Kubernetes

Starter manifests live in `deployment/k8s`. Build and push images first:

```bash
docker build -t shank/backend:1.0.0 -f backend/Dockerfile .
docker build -t shank/frontend:1.0.0 -f frontend/Dockerfile .
kubectl apply -f deployment/k8s/backend.yaml
```
