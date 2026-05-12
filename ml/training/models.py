from __future__ import annotations

from typing import Any

import numpy as np


class ProbabilityCalibratedModel:
    """Wrap a classifier with a lightweight probability calibrator."""

    def __init__(
        self,
        base_model: Any,
        calibrator: Any,
        method: str,
        calibration_feature_columns: list[str] | None = None,
    ) -> None:
        self.base_model = base_model
        self.calibrator = calibrator
        self.method = method
        self.calibration_feature_columns = calibration_feature_columns or []

    def predict_proba(self, rows: Any) -> np.ndarray:
        matrix = self._calibration_matrix(rows)
        calibrated = self.calibrator.predict_proba(matrix)[:, 1]
        calibrated = np.clip(calibrated, 0.0, 1.0)
        return np.column_stack([1.0 - calibrated, calibrated])

    def predict(self, rows: Any) -> np.ndarray:
        return (self.predict_proba(rows)[:, 1] >= 0.5).astype(int)

    def _calibration_matrix(self, rows: Any) -> np.ndarray:
        raw = self.base_model.predict_proba(rows)[:, 1].reshape(-1, 1)
        feature_columns = getattr(self, "calibration_feature_columns", [])
        if not feature_columns:
            return raw
        feature_values = rows[feature_columns].to_numpy(dtype=float)
        return np.column_stack([raw, feature_values])
