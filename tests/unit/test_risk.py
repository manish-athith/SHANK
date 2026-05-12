from app.services.risk import RiskScoringEngine


def test_risk_score_maps_to_high_severity():
    result = RiskScoringEngine().score(0.9, 0.5, threat_intel_hit=True)

    assert result.risk_score >= 70
    assert result.severity in {"high", "critical"}
    assert result.confidence >= 90


def test_low_probability_stays_low_without_intel():
    result = RiskScoringEngine().score(0.1, 0.1, threat_intel_hit=False)

    assert result.risk_score < 45
    assert result.severity == "low"

