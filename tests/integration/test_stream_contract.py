from app.services.feature_extraction import FeatureExtractor
from app.services.ml_inference import MLInferenceEngine


def test_stream_event_contract_can_be_scored():
    event = {
        "source": "test-proxy",
        "event_type": "http",
        "url": "http://account-verify-login.example.test/session?id=123456",
        "headers": {},
        "attachments": [],
    }
    prediction = MLInferenceEngine().predict(event)

    assert set(prediction) == {"model_name", "phishing_probability", "anomaly_score", "features"}
    assert 0 <= prediction["phishing_probability"] <= 1
    assert 0 <= prediction["anomaly_score"] <= 1
    assert len(FeatureExtractor().vectorize(prediction["features"])) > 0

