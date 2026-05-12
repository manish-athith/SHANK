from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from app.core.config import get_settings
from app.core.logging import logger
from app.services.feature_extraction import FeatureExtractor


class HeuristicFallbackModel:
    """Deterministic fallback keeps inference available before first training run."""

    def predict_proba(self, rows: Any) -> np.ndarray:
        scores: list[float] = []
        for row in _as_row_lists(rows):
            url_length, _, _, query_length, entropy, digits, _, hyphens, _, at_symbol, ip_host, https, keywords, *_ = row
            score = 0.08
            score += min(url_length / 220, 0.25)
            score += min(query_length / 120, 0.12)
            score += min(entropy / 8, 0.16)
            score += min(digits / 30, 0.12)
            score += min(hyphens / 8, 0.08)
            score += at_symbol * 0.12 + ip_host * 0.16 + keywords * 0.05
            score -= https * 0.08
            score = max(0.01, min(0.99, score))
            scores.append(score)
        return np.array([[1 - score, score] for score in scores])


class HeuristicAnomalyModel:
    def score_samples(self, rows: Any) -> np.ndarray:
        values = []
        for row in _as_row_lists(rows):
            values.append(-0.2 - min((row[0] + row[5] + row[13] * 10) / 350, 0.8))
        return np.array(values)


def _as_row_lists(rows: Any) -> list[list[float]]:
    if hasattr(rows, "to_numpy"):
        return rows.to_numpy(dtype=float).tolist()
    if isinstance(rows, np.ndarray):
        return rows.astype(float).tolist()
    return rows


def _model_feature_columns(model: Any) -> list[str] | None:
    if hasattr(model, "feature_names_in_"):
        return list(model.feature_names_in_)
    if hasattr(model, "base_model"):
        return _model_feature_columns(model.base_model)
    if hasattr(model, "get_booster"):
        names = model.get_booster().feature_names
        return list(names) if names else None
    return None


def _align_feature_frame(frame: pd.DataFrame, model: Any) -> pd.DataFrame:
    columns = _model_feature_columns(model)
    if not columns:
        return frame
    aligned = frame.copy()
    for column in columns:
        if column not in aligned.columns:
            aligned[column] = 0.0
    return aligned[columns]


class MLInferenceEngine:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.extractor = FeatureExtractor()
        self.phishing_model: Any = self._load_model(
            self.settings.phishing_model_path,
            HeuristicFallbackModel(),
            "phishing_classifier",
        )
        self.anomaly_model: Any = self._load_model(
            self.settings.anomaly_model_path,
            HeuristicAnomalyModel(),
            "isolation_forest",
        )

    def _load_model(self, path: str, fallback: Any, name: str) -> Any:
        model_path = Path(path)
        if model_path.exists():
            logger.info("model_loaded", name=name, path=str(model_path))
            return joblib.load(model_path)
        logger.warning("model_missing_using_fallback", name=name, path=str(model_path))
        return fallback

    def predict(self, event: dict[str, Any]) -> dict[str, Any]:
        features = self.extractor.extract(event)
        feature_frame = self.extractor.to_frame(features)
        phishing_frame = _align_feature_frame(feature_frame, self.phishing_model)
        anomaly_frame = _align_feature_frame(feature_frame, self.anomaly_model)
        proba = self.phishing_model.predict_proba(phishing_frame)[0]
        phishing_probability = float(proba[1])
        raw_anomaly = float(self.anomaly_model.score_samples(anomaly_frame)[0])
        anomaly_score = max(0.0, min(1.0, abs(raw_anomaly)))
        return {
            "model_name": "xgboost_phishing+isolation_forest",
            "phishing_probability": phishing_probability,
            "anomaly_score": anomaly_score,
            "features": features,
        }
