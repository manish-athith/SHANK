# Sample Live Detection Outputs

## High-Risk URL

```json
{
  "type": "alert",
  "alert": {
    "severity": "high",
    "risk_score": 83,
    "title": "Suspicious url detected",
    "description": "http://paypal-account-verify-login.secure-update.example.com/session?id=839292 scored 83/100"
  }
}
```

## Benign URL

```json
{
  "risk_score": 22,
  "severity": "low",
  "confidence": 88.4,
  "phishing_probability": 0.11,
  "anomaly_score": 0.18,
  "alert_created": false
}
```

