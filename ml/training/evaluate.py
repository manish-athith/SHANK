from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score

from app.services.feature_extraction import FeatureExtractor


def evaluate(dataset: Path, model_path: Path) -> dict:
    extractor = FeatureExtractor()
    model = joblib.load(model_path)
    frame = pd.read_csv(dataset).dropna(subset=["url", "label"])
    rows = [extractor.vectorize(extractor.extract({"url": url})) for url in frame["url"]]
    y_true = frame["label"].astype(int)
    probability = model.predict_proba(rows)[:, 1]
    y_pred = (probability >= 0.5).astype(int)
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    report["roc_auc"] = roc_auc_score(y_true, probability) if y_true.nunique() > 1 else 0.0
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate SHANK phishing classifier.")
    parser.add_argument("--dataset", default="datasets/phishing_urls_seed.csv")
    parser.add_argument("--model", default="ml/models/phishing_xgb.joblib")
    args = parser.parse_args()
    print(json.dumps(evaluate(Path(args.dataset), Path(args.model)), indent=2))


if __name__ == "__main__":
    main()

