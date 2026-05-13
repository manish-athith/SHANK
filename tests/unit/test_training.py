from __future__ import annotations

import joblib
import json
import numpy as np
import pandas as pd
import pytest

from app.services.feature_extraction import FeatureExtractor
from ml.training.models import ProbabilityCalibratedModel
from ml.training import train as train_module
from scripts.evaluate_manual_urls import evaluate_urls, load_manual_validation


def test_phiusiil_label_conversion(tmp_path):
    dataset = tmp_path / "phi.csv"
    dataset.write_text(
        "FILENAME,URL,Domain,label\n"
        "a.txt,https://legit.example.com,legit.example.com,1\n"
        "b.txt,http://login-verify.example.test,login-verify.example.test,0\n",
        encoding="utf-8",
    )

    prepared = train_module.load_dataset(dataset)

    assert prepared.spec.dataset_type == "phiusiil"
    assert prepared.frame.set_index("url").loc["https://legit.example.com", "label"] == 0
    assert prepared.frame.set_index("url").loc["http://login-verify.example.test", "label"] == 1


def test_training_loader_drops_invalid_rows_and_deduplicates(tmp_path):
    dataset = tmp_path / "seed.csv"
    dataset.write_text(
        "url,label\n"
        "https://good.example.com,0\n"
        "https://good.example.com,0\n"
        ",1\n"
        "not-a-url,1\n"
        "http://bad.example.test/login,1\n"
        "https://bad-label.example.com,unknown\n",
        encoding="utf-8",
    )

    prepared = train_module.load_dataset(dataset)

    assert prepared.original_rows == 6
    assert prepared.frame["url"].tolist() == [
        "https://good.example.com",
        "http://bad.example.test/login",
    ]
    assert prepared.frame["label"].tolist() == [0, 1]


def test_feature_dataframe_uses_stable_runtime_columns():
    extractor = FeatureExtractor()
    features = extractor.extract({"url": "https://secure.example.com/login"})
    frame = extractor.to_frame(features)

    assert frame.columns.tolist() == extractor.feature_order
    assert extractor.vectorize(features) == frame.iloc[0].tolist()


def test_training_writes_loadable_model_files(tmp_path, monkeypatch):
    dataset = tmp_path / "seed.csv"
    rows = ["url,label"]
    for index in range(16):
        rows.append(f"https://benign-{index}.example.com/docs,0")
        rows.append(f"http://verify-login-{index}.example.test/account?token={index},1")
    dataset.write_text("\n".join(rows), encoding="utf-8")

    monkeypatch.setattr(train_module, "XGBOOST_AVAILABLE", False)
    model_dir = tmp_path / "models"
    metrics_path = model_dir / "metrics.json"

    metrics = train_module.train(dataset, model_dir, metrics_path)

    assert (model_dir / "phishing_xgb.joblib").exists()
    assert (model_dir / "anomaly_iforest.joblib").exists()
    assert metrics_path.exists()
    classifier = joblib.load(model_dir / "phishing_xgb.joblib")
    anomaly = joblib.load(model_dir / "anomaly_iforest.joblib")
    assert hasattr(classifier, "predict_proba")
    assert hasattr(anomaly, "score_samples")
    assert metrics["features"] == FeatureExtractor.feature_order


def test_probability_calibrator_clips_extreme_probabilities():
    class Base:
        def predict_proba(self, rows):
            return np.array([[0.0, 1.0], [1.0, 0.0]])

    class Calibrator:
        def predict_proba(self, rows):
            return np.array([[0.0, 1.0], [1.0, 0.0]])

    model = ProbabilityCalibratedModel(Base(), Calibrator(), "test")
    probabilities = model.predict_proba(pd.DataFrame({"x": [1, 2]}))[:, 1]

    assert probabilities.tolist() == [0.985, 0.015]


def test_manual_validation_csv_schema():
    frame = load_manual_validation(train_module.ROOT_DIR / "datasets" / "manual_validation_urls.csv")

    assert {"url", "expected_label", "notes"} <= set(frame.columns)
    assert (frame["expected_label"] == 0).sum() >= 100
    assert (frame["expected_label"] == 1).sum() >= 100


def test_manual_holdout_csv_schema():
    frame = load_manual_validation(train_module.ROOT_DIR / "datasets" / "manual_holdout_urls.csv")

    assert {"url", "expected_label", "notes"} <= set(frame.columns)
    assert "https://www.zepto.com" in set(frame["url"])
    assert "https://www.palantir.com" in set(frame["url"])
    assert "https://www.amazon.in" in set(frame["url"])
    assert "https://www.paypal.com/in/home" in set(frame["url"])
    assert "http://paypal-login-security-check.example.com/update-password" in set(frame["url"])


class StubMLInferenceEngine:
    def predict(self, event):
        is_phishing = "login" in event["url"]
        return {
            "phishing_probability": 0.95 if is_phishing else 0.05,
            "anomaly_score": 0.2,
        }


def test_manual_evaluator_output_schema(tmp_path, monkeypatch):
    dataset = tmp_path / "manual.csv"
    dataset.write_text(
        "url,expected_label,notes\n"
        "https://www.microsoft.com/en-us/security,0,benign\n"
        "http://login-microsoftonline-security-check.example.ru/verify,1,synthetic\n",
        encoding="utf-8",
    )
    results_path = tmp_path / "results.csv"
    summary_path = tmp_path / "summary.json"
    monkeypatch.setattr("scripts.evaluate_manual_urls.MLInferenceEngine", StubMLInferenceEngine)

    summary = evaluate_urls(dataset, results_path, summary_path)
    results = pd.read_csv(results_path)

    assert summary["total"] == 2
    assert {
        "url",
        "expected_label",
        "phishing_probability",
        "anomaly_score",
        "risk_score",
        "severity",
        "predicted_label",
        "correct",
    } <= set(results.columns)
    assert {
        "high_risk_benign_count",
        "critical_risk_benign_count",
        "saturated_high_probability_count",
        "saturated_low_probability_count",
    } <= set(summary)
    assert summary_path.exists()


def _load_current_holdout_results():
    metrics_path = train_module.ROOT_DIR / "ml" / "models" / "metrics.json"
    results_path = train_module.ROOT_DIR / "ml" / "models" / "manual_holdout_results.csv"
    if not results_path.exists():
        pytest.skip("manual holdout results are generated by scripts/evaluate_manual_urls.py")
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    if metrics.get("calibration_method") != "feature_aware_logistic_validation_split":
        pytest.skip("manual holdout results were generated before feature-aware calibration")
    return pd.read_csv(results_path)


@pytest.mark.parametrize(
    "url",
    [
        "https://www.zepto.com",
        "https://www.palantir.com",
        "https://www.amazon.in",
        "https://www.paypal.com/in/home",
        "https://www.microsoft.com/en-us/security",
        "https://github.com",
        "https://www.cloudflare.com/learning/security/",
    ],
)
def test_acceptance_benign_urls_not_high_or_critical(url):
    results = _load_current_holdout_results()
    row = results.loc[results["url"] == url].iloc[0]
    assert row["predicted_label"] == 0
    assert row["severity"] in {"low", "medium"}


@pytest.mark.parametrize(
    "url",
    [
        "http://paypal-login-security-check.example.com/update-password",
        "http://amazon-account-verify.example.net/billing/update",
        "http://login-microsoftonline-security-check.example.test/verify/account/password-reset",
        "http://zepto-offer-wallet-login.example.com/verify",
        "http://palantir-careers-login.example.net/account/secure",
    ],
)
def test_acceptance_phishing_urls_stay_high_or_critical(url):
    results = _load_current_holdout_results()
    row = results.loc[results["url"] == url].iloc[0]
    assert row["predicted_label"] == 1
    assert row["severity"] in {"high", "critical"}
