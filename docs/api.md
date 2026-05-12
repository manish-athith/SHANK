# API Documentation

Swagger UI is available at `http://localhost:8000/docs`.

## Authentication

```powershell
$login = Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/auth/login" -ContentType "application/x-www-form-urlencoded" -Body "username=admin@shank.local&password=ChangeMe123!"
$headers = @{ Authorization = "Bearer $($login.access_token)" }
```

Use the returned bearer token for protected endpoints.

## URL Prediction

```powershell
$body = @{ url = "http://secure-login-paypa1.example.info/update-billing"; source = "powershell" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/predict-url" -Headers $headers -ContentType "application/json" -Body $body
```

Example response:

```json
{
  "event_id": "7e5b6b33-d4c3-43e2-93d2-59309f20caaa",
  "risk_score": 83,
  "severity": "high",
  "confidence": 91.2,
  "phishing_probability": 0.91,
  "anomaly_score": 0.44,
  "features": {
    "url_length": 61.0,
    "entropy": 4.32,
    "suspicious_keyword_count": 4.0
  },
  "alert_created": true
}
```

## Threat Check

`POST /api/v1/threat-check`

```powershell
$body = @{ indicator = "example-phish.test"; indicator_type = "domain" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/threat-check" -Headers $headers -ContentType "application/json" -Body $body
```

## Live Alerts

Connect to:

`ws://localhost:8000/api/v1/alerts/live?token=<jwt>`

Missing or invalid JWTs are closed with WebSocket policy violation code `1008`.

## Health

`GET /api/v1/health` reports PostgreSQL, Redis, model/fallback, and Kafka configuration status. Kafka is reported as configured/unverified by the health endpoint; the stream processor and backend logs show consumer startup.
