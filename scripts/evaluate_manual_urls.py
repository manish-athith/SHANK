from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
for import_path in (str(ROOT_DIR), str(BACKEND_DIR)):
    if import_path not in sys.path:
        sys.path.insert(0, import_path)

import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

from app.core.config import get_settings
from app.services.ml_inference import MLInferenceEngine
from app.services.risk import RiskScoringEngine


REQUIRED_COLUMNS = {"url", "expected_label", "notes"}


def load_manual_validation(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path)
    missing = REQUIRED_COLUMNS - set(frame.columns)
    if missing:
        raise ValueError(f"Manual validation CSV missing columns: {sorted(missing)}")
    frame = frame.dropna(subset=["url", "expected_label"]).copy()
    frame["url"] = frame["url"].astype(str).str.strip()
    frame["expected_label"] = pd.to_numeric(frame["expected_label"], errors="coerce")
    frame = frame.loc[frame["url"].ne("") & frame["expected_label"].isin([0, 1])].copy()
    frame["expected_label"] = frame["expected_label"].astype(int)
    return frame.reset_index(drop=True)


def evaluate_urls(
    input_path: Path,
    results_path: Path,
    summary_path: Path,
) -> dict[str, Any]:
    settings = get_settings()
    engine = MLInferenceEngine()
    risk = RiskScoringEngine()
    frame = load_manual_validation(input_path)

    rows: list[dict[str, Any]] = []
    for record in frame.to_dict(orient="records"):
        ml_result = engine.predict({"url": record["url"], "event_type": "url", "source": "manual_validation"})
        risk_result = risk.score(
            ml_result["phishing_probability"],
            ml_result["anomaly_score"],
            threat_intel_hit=False,
        )
        predicted_label = int(risk_result.risk_score >= settings.risk_alert_threshold)
        rows.append(
            {
                "url": record["url"],
                "expected_label": int(record["expected_label"]),
                "notes": record.get("notes", ""),
                "phishing_probability": ml_result["phishing_probability"],
                "anomaly_score": ml_result["anomaly_score"],
                "risk_score": risk_result.risk_score,
                "severity": risk_result.severity,
                "predicted_label": predicted_label,
                "correct": predicted_label == int(record["expected_label"]),
            }
        )

    results = pd.DataFrame(rows)
    y_true = results["expected_label"].astype(int)
    y_pred = results["predicted_label"].astype(int)
    false_positives = results.loc[(y_true == 0) & (y_pred == 1)].to_dict(orient="records")
    false_negatives = results.loc[(y_true == 1) & (y_pred == 0)].to_dict(orient="records")
    summary: dict[str, Any] = {
        "total": int(len(results)),
        "benign_total": int((y_true == 0).sum()),
        "phishing_total": int((y_true == 1).sum()),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "false_positive_count": int(len(false_positives)),
        "false_negative_count": int(len(false_negatives)),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }

    results_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(results_path, index=False)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate SHANK models on manual URL validation cases.")
    parser.add_argument("--input", default="datasets/manual_validation_urls.csv")
    parser.add_argument("--results", default="ml/models/manual_validation_results.csv")
    parser.add_argument("--summary", default="ml/models/manual_validation_summary.json")
    args = parser.parse_args()
    summary = evaluate_urls(Path(args.input), Path(args.results), Path(args.summary))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
