from dataclasses import dataclass


@dataclass(frozen=True)
class RiskResult:
    risk_score: int
    severity: str
    confidence: float


class RiskScoringEngine:
    def score(
        self,
        phishing_probability: float,
        anomaly_score: float,
        threat_intel_hit: bool = False,
    ) -> RiskResult:
        probability_component = phishing_probability * 72
        anomaly_component = max(0.0, min(1.0, anomaly_score)) * 18
        intel_component = 10 if threat_intel_hit else 0
        risk_score = int(max(0, min(100, round(probability_component + anomaly_component + intel_component))))

        if risk_score >= 85:
            severity = "critical"
        elif risk_score >= 70:
            severity = "high"
        elif risk_score >= 45:
            severity = "medium"
        else:
            severity = "low"

        confidence = round(max(phishing_probability, 1 - phishing_probability) * 100, 2)
        return RiskResult(risk_score=risk_score, severity=severity, confidence=confidence)

