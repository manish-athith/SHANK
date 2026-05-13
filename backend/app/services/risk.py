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
        features: dict | None = None,
    ) -> RiskResult:
        feature_values = features or {}
        probability = max(0.0, min(1.0, phishing_probability))
        anomaly = max(0.0, min(1.0, anomaly_score))

        probability_component = probability * 58
        anomaly_component = anomaly * 10
        impersonation_component = min(float(feature_values.get("brand_impersonation_score", 0.0)), 4.0) * 7
        suspicious_tld_component = float(feature_values.get("suspicious_tld", 0.0)) * 5
        credential_component = min(float(feature_values.get("credential_keyword_count", 0.0)), 4.0) * 3
        ecommerce_component = min(float(feature_values.get("ecommerce_keyword_count", 0.0)), 4.0) * 3
        financial_component = min(float(feature_values.get("financial_keyword_count", 0.0)), 4.0) * 2
        suspicious_path_component = min(float(feature_values.get("suspicious_path_keyword_count", 0.0)), 4.0) * 2
        https_component = -4 if float(feature_values.get("https", 0.0)) else 3
        legitimate_domain_reduction = 0
        if float(feature_values.get("is_known_legitimate_registered_domain", 0.0)):
            legitimate_domain_reduction = 16
            if credential_component or suspicious_path_component:
                legitimate_domain_reduction = 8
        intel_component = 10 if threat_intel_hit else 0
        risk_score = int(
            max(
                0,
                min(
                    100,
                    round(
                        probability_component
                        + anomaly_component
                        + impersonation_component
                        + suspicious_tld_component
                        + credential_component
                        + ecommerce_component
                        + financial_component
                        + suspicious_path_component
                        + https_component
                        + intel_component
                        - legitimate_domain_reduction
                    ),
                ),
            )
        )

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
