# Database Schema

## Tables

`users`

- JWT login identities, password hashes, RBAC roles, active status.

`phishing_events`

- Raw event payloads, extracted domain, sender/recipient, subject, normalized features, created timestamp.

`model_predictions`

- Model name, phishing probability, anomaly score, confidence, feature snapshot, event relationship.

`alerts`

- Severity, risk score, analyst status, dedupe key, event and prediction references.

`threat_feeds`

- OpenPhish, URLHaus, PhishTank, or custom indicators with metadata and timestamps.

`audit_logs`

- Actor, action, resource, details, and immutable timestamp for forensic traceability.

## Indexes

The initial migration creates indexes for:

- user email lookup
- event domain and event time queries
- alert status, severity, risk, dedupe, and created time
- threat indicator lookups
- audit actor/action investigation

Migration file: `backend/migrations/001_init.sql`.

