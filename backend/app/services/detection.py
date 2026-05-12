from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.orm import ModelPrediction, PhishingEvent
from app.services.alert_service import AlertService, serialize_alert
from app.services.feature_extraction import extract_domain
from app.services.ml_inference import MLInferenceEngine
from app.services.risk import RiskScoringEngine
from app.services.threat_intel import ThreatIntelService


class DetectionEngine:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.ml = MLInferenceEngine()
        self.risk = RiskScoringEngine()
        self.threat_intel = ThreatIntelService()
        self.alerts = AlertService()

    async def analyze(self, db: AsyncSession, event: dict[str, Any], persist: bool = True) -> dict[str, Any]:
        domain = extract_domain(event.get("url"))
        threat = await self.threat_intel.local_lookup(db, event.get("url") or domain or "")
        ml_result = self.ml.predict(event)
        risk_result = self.risk.score(
            ml_result["phishing_probability"],
            ml_result["anomaly_score"],
            threat_intel_hit=threat["hit"],
        )

        stored_event: PhishingEvent | None = None
        prediction: ModelPrediction | None = None
        if persist:
            stored_event = PhishingEvent(
                source=event.get("source", "api"),
                event_type=event.get("event_type", "url"),
                url=event.get("url"),
                domain=domain,
                email_sender=event.get("email_sender"),
                recipient=event.get("recipient"),
                subject=event.get("subject"),
                raw_payload=event,
                parsed_features=ml_result["features"],
            )
            db.add(stored_event)
            await db.flush()
            prediction = ModelPrediction(
                event_id=stored_event.id,
                model_name=ml_result["model_name"],
                phishing_probability=ml_result["phishing_probability"],
                anomaly_score=ml_result["anomaly_score"],
                confidence=risk_result.confidence,
                features=ml_result["features"],
            )
            db.add(prediction)
            await db.flush()

        alert_created = False
        alert_payload: dict[str, Any] | None = None
        if risk_result.risk_score >= self.settings.risk_alert_threshold:
            alert = await self.alerts.create_alert(
                db,
                event_id=stored_event.id if stored_event else None,
                prediction_id=prediction.id if prediction else None,
                risk_score=risk_result.risk_score,
                severity=risk_result.severity,
                title=f"Suspicious {event.get('event_type', 'url')} detected",
                description=f"{event.get('url') or event.get('subject') or 'Event'} scored {risk_result.risk_score}/100",
                dedupe_key=f"{domain or event.get('url') or event.get('subject')}:{risk_result.severity}",
            )
            alert_created = alert is not None
            alert_payload = serialize_alert(alert) if alert else None

        return {
            "event_id": stored_event.id if stored_event else None,
            "risk_score": risk_result.risk_score,
            "severity": risk_result.severity,
            "confidence": risk_result.confidence,
            "phishing_probability": ml_result["phishing_probability"],
            "anomaly_score": ml_result["anomaly_score"],
            "features": ml_result["features"],
            "threat_intel": threat,
            "alert_created": alert_created,
            "alert": alert_payload,
        }
