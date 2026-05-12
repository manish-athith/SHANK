CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(320) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    roles JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS phishing_events (
    id VARCHAR(36) PRIMARY KEY,
    source VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    url TEXT,
    domain VARCHAR(255),
    email_sender VARCHAR(320),
    recipient VARCHAR(320),
    subject TEXT,
    raw_payload JSONB NOT NULL,
    parsed_features JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS model_predictions (
    id VARCHAR(36) PRIMARY KEY,
    event_id VARCHAR(36) REFERENCES phishing_events(id),
    model_name VARCHAR(128) NOT NULL,
    phishing_probability DOUBLE PRECISION NOT NULL,
    anomaly_score DOUBLE PRECISION NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    features JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id VARCHAR(36) PRIMARY KEY,
    event_id VARCHAR(36) REFERENCES phishing_events(id),
    prediction_id VARCHAR(36) REFERENCES model_predictions(id),
    severity VARCHAR(32) NOT NULL,
    risk_score INTEGER NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'open',
    dedupe_key VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_feeds (
    id VARCHAR(36) PRIMARY KEY,
    provider VARCHAR(64) NOT NULL,
    indicator VARCHAR(512) NOT NULL,
    indicator_type VARCHAR(32) NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_provider_indicator ON threat_feeds(provider, indicator);

CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    actor VARCHAR(320) NOT NULL,
    action VARCHAR(128) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_users_email ON users(email);
CREATE INDEX IF NOT EXISTS ix_events_source ON phishing_events(source);
CREATE INDEX IF NOT EXISTS ix_events_type ON phishing_events(event_type);
CREATE INDEX IF NOT EXISTS ix_events_domain ON phishing_events(domain);
CREATE INDEX IF NOT EXISTS ix_events_created ON phishing_events(created_at);
CREATE INDEX IF NOT EXISTS ix_events_domain_created ON phishing_events(domain, created_at);
CREATE INDEX IF NOT EXISTS ix_predictions_model ON model_predictions(model_name);
CREATE INDEX IF NOT EXISTS ix_predictions_created ON model_predictions(created_at);
CREATE INDEX IF NOT EXISTS ix_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS ix_alerts_risk ON alerts(risk_score);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS ix_alerts_dedupe ON alerts(dedupe_key);
CREATE INDEX IF NOT EXISTS ix_alerts_status_created ON alerts(status, created_at);
CREATE INDEX IF NOT EXISTS ix_threat_indicator ON threat_feeds(indicator);
CREATE INDEX IF NOT EXISTS ix_threat_provider ON threat_feeds(provider);
CREATE INDEX IF NOT EXISTS ix_audit_actor ON audit_logs(actor);
CREATE INDEX IF NOT EXISTS ix_audit_action ON audit_logs(action);
