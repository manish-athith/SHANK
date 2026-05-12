from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:  # Keeps local smoke tests usable before dependency installation.
    from sklearn.ensemble import GradientBoostingClassifier
    XGBOOST_AVAILABLE = False

from app.services.feature_extraction import FeatureExtractor


def load_dataset(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path)
    required = {"url", "label"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"Dataset missing required columns: {sorted(missing)}")
    return frame.dropna(subset=["url", "label"])


def featurize(frame: pd.DataFrame, extractor: FeatureExtractor) -> tuple[pd.DataFrame, pd.Series]:
    rows = []
    for record in frame.to_dict(orient="records"):
        features = extractor.extract({"url": record["url"], "event_type": "url", "source": "dataset"})
        rows.append(extractor.vectorize(features))
    return pd.DataFrame(rows, columns=extractor.feature_order), frame["label"].astype(int)


def train(dataset: Path, model_dir: Path, metrics_path: Path) -> dict[str, float]:
    model_dir.mkdir(parents=True, exist_ok=True)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    extractor = FeatureExtractor()
    frame = load_dataset(dataset)
    x, y = featurize(frame, extractor)
    stratify = y if y.nunique() > 1 and y.value_counts().min() >= 2 else None
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.25, random_state=42, stratify=stratify
    )

    if XGBOOST_AVAILABLE:
        classifier = XGBClassifier(
            n_estimators=160,
            max_depth=4,
            learning_rate=0.06,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            random_state=42,
        )
    else:
        classifier = GradientBoostingClassifier(
            n_estimators=160,
            max_depth=4,
            learning_rate=0.06,
            random_state=42,
        )
    classifier.fit(x_train, y_train)
    probabilities = classifier.predict_proba(x_test)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)

    benign_rows = x_train[y_train == 0] if (y_train == 0).any() else x_train
    anomaly = IsolationForest(n_estimators=120, contamination=0.08, random_state=42)
    anomaly.fit(benign_rows)

    metrics = {
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, predictions, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, probabilities)), 4) if y_test.nunique() > 1 else 0.0,
        "dataset_rows": int(len(frame)),
        "dataset_note": "Seed data is for smoke testing only; use real feeds before claiming model quality.",
        "features": extractor.feature_order,
    }

    joblib.dump(classifier, model_dir / "phishing_xgb.joblib")
    joblib.dump(anomaly, model_dir / "anomaly_iforest.joblib")
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train SHANK phishing detection models.")
    parser.add_argument("--dataset", default="datasets/phishing_urls_seed.csv")
    parser.add_argument("--model-dir", default="ml/models")
    parser.add_argument("--metrics", default="ml/models/metrics.json")
    args = parser.parse_args()
    metrics = train(Path(args.dataset), Path(args.model_dir), Path(args.metrics))
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
