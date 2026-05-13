from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
for import_path in (str(ROOT_DIR), str(BACKEND_DIR)):
    if import_path not in sys.path:
        sys.path.insert(0, import_path)

import joblib
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression

try:
    from xgboost import XGBClassifier

    XGBOOST_AVAILABLE = True
except ImportError:  # Keeps local smoke tests usable before dependency installation.
    XGBOOST_AVAILABLE = False

from app.services.feature_extraction import FeatureExtractor, extract_domain
from app.core.config import get_settings
from app.services.risk import RiskScoringEngine
from ml.training.models import ProbabilityCalibratedModel


@dataclass(frozen=True)
class DatasetSpec:
    dataset_type: str
    url_column: str
    label_column: str
    label_mapping: dict[str, int]
    dataset_note: str


@dataclass(frozen=True)
class PreparedDataset:
    frame: pd.DataFrame
    spec: DatasetSpec
    original_rows: int


SEED_NOTE = (
    "Seed dataset is smoke-test-only and should not be used to claim production model performance."
)
PHIUSIIL_NOTE = (
    "PhiUSIIL training uses only the URL column and SHANK runtime feature extractor; "
    "precomputed dataset columns are intentionally ignored."
)
CALIBRATION_FEATURE_COLUMNS = [
    "query_length",
    "suspicious_keyword_count",
    "suspicious_path_keyword_count",
    "suspicious_tld",
    "brand_keyword_not_in_registered_domain",
    "known_brand_registered_domain",
    "is_known_legitimate_registered_domain",
    "brand_in_registered_domain",
    "brand_in_subdomain",
    "brand_in_path",
    "brand_impersonation_score",
    "hostname_is_registered_domain",
    "path_token_count",
    "domain_token_count",
    "domain_entropy",
    "path_entropy",
    "credential_keyword_count",
    "ecommerce_keyword_count",
    "financial_keyword_count",
    "punycode_detected",
    "url_shortener_detected",
    "has_login_keyword",
    "has_verify_keyword",
    "has_account_keyword",
    "has_password_keyword",
]
MANUAL_CALIBRATION_WEIGHT = 900.0


def detect_dataset_spec(path: Path) -> DatasetSpec:
    columns = set(pd.read_csv(path, nrows=0, encoding_errors="replace").columns)
    if {"URL", "label"} <= columns:
        return DatasetSpec(
            dataset_type="phiusiil",
            url_column="URL",
            label_column="label",
            label_mapping={
                "source_label_0": 1,
                "source_label_1": 0,
                "positive_class": 1,
            },
            dataset_note=PHIUSIIL_NOTE,
        )
    if {"url", "label"} <= columns:
        return DatasetSpec(
            dataset_type="seed",
            url_column="url",
            label_column="label",
            label_mapping={
                "source_label_0": 0,
                "source_label_1": 1,
                "positive_class": 1,
            },
            dataset_note=SEED_NOTE,
        )
    raise ValueError(
        "Dataset missing required columns. Expected either ['url', 'label'] "
        "or PhiUSIIL columns ['URL', 'label']."
    )


def _normalize_urls(values: pd.Series) -> pd.Series:
    return values.astype("string").str.strip()


def _valid_url_mask(urls: pd.Series) -> pd.Series:
    has_text = urls.notna() & (urls != "") & (urls.str.lower() != "nan")
    has_domain = urls.apply(
        lambda value: _has_valid_hostname(str(value)) if pd.notna(value) else False
    )
    return has_text & has_domain


def _has_valid_hostname(url: str) -> bool:
    domain = extract_domain(url)
    if not domain:
        return False
    return "." in domain or bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain))


def load_dataset(path: Path) -> PreparedDataset:
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    spec = detect_dataset_spec(path)
    raw = pd.read_csv(
        path,
        usecols=[spec.url_column, spec.label_column],
        low_memory=False,
        encoding_errors="replace",
    )
    original_rows = int(len(raw))
    raw = raw.rename(columns={spec.url_column: "url", spec.label_column: "source_label"})
    raw["url"] = _normalize_urls(raw["url"])
    raw["source_label"] = pd.to_numeric(raw["source_label"], errors="coerce")

    clean = raw.loc[_valid_url_mask(raw["url"])].copy()
    clean = clean.loc[clean["source_label"].isin([0, 1])].copy()
    clean["source_label"] = clean["source_label"].astype(int)
    if spec.dataset_type == "phiusiil":
        clean["label"] = clean["source_label"].map({0: 1, 1: 0}).astype(int)
    else:
        clean["label"] = clean["source_label"].astype(int)

    clean = clean.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    return PreparedDataset(clean[["url", "label"]], spec, original_rows)


def featurize(frame: pd.DataFrame, extractor: FeatureExtractor) -> tuple[pd.DataFrame, pd.Series]:
    feature_rows = [
        extractor.extract({"url": url, "event_type": "url", "source": "dataset"})
        for url in frame["url"].tolist()
    ]
    x = extractor.to_frame(feature_rows)
    y = frame["label"].astype(int).reset_index(drop=True)
    return x, y


def _build_classifier() -> Any:
    if XGBOOST_AVAILABLE:
        return XGBClassifier(
            n_estimators=160,
            max_depth=4,
            learning_rate=0.06,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            random_state=42,
        )
    return GradientBoostingClassifier(
        n_estimators=160,
        max_depth=4,
        learning_rate=0.06,
        random_state=42,
    )


def _load_manual_calibration_frame(extractor: FeatureExtractor) -> tuple[pd.DataFrame, pd.Series] | None:
    manual_path = ROOT_DIR / "datasets" / "calibration_guardrail_urls.csv"
    if not manual_path.exists():
        manual_path = ROOT_DIR / "datasets" / "manual_validation_urls.csv"
    if not manual_path.exists():
        return None
    from scripts.evaluate_manual_urls import load_manual_validation

    manual = load_manual_validation(manual_path)
    x_manual, y_manual = featurize(
        manual.rename(columns={"expected_label": "label"})[["url", "label"]],
        extractor,
    )
    return x_manual, y_manual


def _calibration_matrix(base_model: Any, frame: pd.DataFrame) -> Any:
    raw_probabilities = base_model.predict_proba(frame)[:, 1].reshape(-1, 1)
    feature_values = frame[CALIBRATION_FEATURE_COLUMNS].to_numpy(dtype=float)
    return pd.DataFrame(
        data=pd.concat(
            [
                pd.DataFrame(raw_probabilities, columns=["raw_phishing_probability"]).reset_index(drop=True),
                pd.DataFrame(feature_values, columns=CALIBRATION_FEATURE_COLUMNS).reset_index(drop=True),
            ],
            axis=1,
        )
    ).to_numpy(dtype=float)


def _calibrate_classifier(
    base_model: Any,
    x_validation: pd.DataFrame,
    y_validation: pd.Series,
    extractor: FeatureExtractor,
) -> Any:
    calibration_x = x_validation.copy()
    calibration_y = y_validation.reset_index(drop=True).copy()
    sample_weights = pd.Series([1.0] * len(calibration_y))
    manual_calibration = _load_manual_calibration_frame(extractor)
    if manual_calibration:
        x_manual, y_manual = manual_calibration
        calibration_x = pd.concat([calibration_x, x_manual], ignore_index=True)
        calibration_y = pd.concat([calibration_y, y_manual], ignore_index=True)
        sample_weights = pd.concat(
            [sample_weights, pd.Series([MANUAL_CALIBRATION_WEIGHT] * len(y_manual))],
            ignore_index=True,
        )

    matrix = _calibration_matrix(base_model, calibration_x)
    calibrator = LogisticRegression(random_state=42, max_iter=1000)
    calibrator.fit(matrix, calibration_y, sample_weight=sample_weights)
    return ProbabilityCalibratedModel(
        base_model=base_model,
        calibrator=calibrator,
        method="feature_aware_logistic_validation_split",
        calibration_feature_columns=CALIBRATION_FEATURE_COLUMNS,
    )


def _choose_probability_threshold(y_true: pd.Series, probabilities: Any) -> float:
    best_threshold = 0.5
    best_score = (-1.0, -1.0, -1.0)
    for threshold in [index / 100 for index in range(5, 96)]:
        predictions = (probabilities >= threshold).astype(int)
        precision = float(precision_score(y_true, predictions, zero_division=0))
        recall = float(recall_score(y_true, predictions, zero_division=0))
        f1 = float(f1_score(y_true, predictions, zero_division=0))
        if recall < 0.95:
            continue
        score = (f1, precision, threshold)
        if score > best_score:
            best_score = score
            best_threshold = threshold
    return float(best_threshold)


def _quality_warnings(usable_rows: int, class_counts: dict[int, int], roc_auc: float) -> list[str]:
    warnings: list[str] = []
    if usable_rows < 1000:
        warnings.append("Fewer than 1,000 usable rows; metrics are smoke-test quality only.")
    minority_share = min(class_counts.values()) / usable_rows if usable_rows else 0
    if minority_share < 0.20:
        warnings.append(
            f"Class imbalance warning: minority class is {minority_share:.1%} of usable rows."
        )
    if roc_auc >= 0.999:
        warnings.append(
            "ROC-AUC is suspiciously close to perfect; check for leakage, duplicates, or an overly easy split."
        )
    return warnings


def _evaluate_manual_validation(
    validation_path: Path,
    classifier: Any,
    anomaly: IsolationForest,
    extractor: FeatureExtractor,
) -> dict[str, Any] | None:
    if not validation_path.exists():
        return None

    from scripts.evaluate_manual_urls import load_manual_validation

    settings = get_settings()
    risk = RiskScoringEngine()
    frame = load_manual_validation(validation_path)
    rows: list[dict[str, Any]] = []
    for record in frame.to_dict(orient="records"):
        features = extractor.extract({"url": record["url"], "event_type": "url", "source": "manual_validation"})
        feature_frame = extractor.to_frame(features)
        phishing_probability = float(classifier.predict_proba(feature_frame)[0][1])
        raw_anomaly = float(anomaly.score_samples(feature_frame)[0])
        anomaly_score = max(0.0, min(1.0, abs(raw_anomaly)))
        risk_result = risk.score(phishing_probability, anomaly_score, features=features)
        predicted_label = int(risk_result.risk_score >= settings.risk_alert_threshold)
        rows.append(
            {
                "url": record["url"],
                "expected_label": int(record["expected_label"]),
                "phishing_probability": phishing_probability,
                "anomaly_score": anomaly_score,
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
    high_risk_benign = results.loc[(y_true == 0) & (results["severity"].isin(["high", "critical"]))]
    critical_risk_benign = results.loc[(y_true == 0) & (results["severity"] == "critical")]
    return {
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
        "high_risk_benign_count": int(len(high_risk_benign)),
        "critical_risk_benign_count": int(len(critical_risk_benign)),
        "saturated_high_probability_count": int((results["phishing_probability"] >= 0.99).sum()),
        "saturated_low_probability_count": int((results["phishing_probability"] <= 0.01).sum()),
    }


def train(dataset: Path, model_dir: Path, metrics_path: Path) -> dict[str, Any]:
    model_dir.mkdir(parents=True, exist_ok=True)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)

    extractor = FeatureExtractor()
    prepared = load_dataset(dataset)
    frame = prepared.frame
    usable_rows = int(len(frame))
    class_counts_series = frame["label"].value_counts().reindex([0, 1], fill_value=0)
    class_counts = {int(label): int(count) for label, count in class_counts_series.items()}

    if usable_rows < 4 or frame["label"].nunique() < 2 or min(class_counts.values()) < 2:
        raise ValueError("Training requires at least two usable rows from each class.")

    x, y = featurize(frame, extractor)
    x_train_full, x_test, y_train_full, y_test = train_test_split(
        x,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )
    x_train, x_validation, y_train, y_validation = train_test_split(
        x_train_full,
        y_train_full,
        test_size=0.20,
        random_state=43,
        stratify=y_train_full,
    )

    base_classifier = _build_classifier()
    base_classifier.fit(x_train, y_train)
    classifier = _calibrate_classifier(base_classifier, x_validation, y_validation, extractor)
    validation_probabilities = classifier.predict_proba(x_validation)[:, 1]
    probability_threshold = _choose_probability_threshold(y_validation, validation_probabilities)
    probabilities = classifier.predict_proba(x_test)[:, 1]
    predictions = (probabilities >= probability_threshold).astype(int)

    benign_rows = x_train.loc[y_train == 0]
    anomaly = IsolationForest(n_estimators=120, contamination=0.08, random_state=42)
    anomaly.fit(benign_rows)

    roc_auc = float(roc_auc_score(y_test, probabilities))
    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])
    report = classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["benign", "phishing"],
        output_dict=True,
        zero_division=0,
    )
    warnings = _quality_warnings(usable_rows, class_counts, roc_auc)
    saturated_high = int((probabilities >= 0.99).sum())
    saturated_low = int((probabilities <= 0.01).sum())
    if saturated_high / len(probabilities) > 0.50:
        warnings.append("More than 50% of test probabilities are >= 0.99; calibration may be overconfident.")
    if saturated_low / len(probabilities) > 0.50:
        warnings.append("More than 50% of test probabilities are <= 0.01; calibration may be overconfident.")
    settings = get_settings()
    calibration_guardrail = _evaluate_manual_validation(
        ROOT_DIR / "datasets" / "calibration_guardrail_urls.csv"
        if (ROOT_DIR / "datasets" / "calibration_guardrail_urls.csv").exists()
        else ROOT_DIR / "datasets" / "manual_validation_urls.csv",
        classifier,
        anomaly,
        extractor,
    )
    manual_holdout = _evaluate_manual_validation(
        ROOT_DIR / "datasets" / "manual_holdout_urls.csv",
        classifier,
        anomaly,
        extractor,
    )
    if calibration_guardrail and calibration_guardrail["false_positive_count"]:
        warnings.append(
            f"Calibration guardrail has {calibration_guardrail['false_positive_count']} false positives."
        )
    if manual_holdout and manual_holdout["false_positive_count"]:
        warnings.append(f"Independent manual holdout has {manual_holdout['false_positive_count']} false positives.")
    if manual_holdout and manual_holdout["high_risk_benign_count"]:
        warnings.append(
            f"Independent manual holdout has {manual_holdout['high_risk_benign_count']} high-risk benign URLs."
        )

    metrics: dict[str, Any] = {
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, predictions, zero_division=0)), 4),
        "roc_auc": round(roc_auc, 4),
        "confusion_matrix": matrix.astype(int).tolist(),
        "false_positive_count": int(matrix[0][1]),
        "false_negative_count": int(matrix[1][0]),
        "saturated_high_probability_count": saturated_high,
        "saturated_low_probability_count": saturated_low,
        "classification_report": report,
        "features": extractor.feature_order,
        "dataset_path": str(dataset),
        "original_rows": prepared.original_rows,
        "usable_rows": usable_rows,
        "train_rows": int(len(x_train)),
        "validation_rows": int(len(x_validation)),
        "test_rows": int(len(x_test)),
        "phishing_rows": class_counts[1],
        "benign_rows": class_counts[0],
        "label_mapping": prepared.spec.label_mapping,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_note": prepared.spec.dataset_note,
        "dataset_type": prepared.spec.dataset_type,
        "calibration_method": classifier.method,
        "calibration_feature_columns": CALIBRATION_FEATURE_COLUMNS,
        "manual_calibration_weight": MANUAL_CALIBRATION_WEIGHT,
        "probability_threshold": probability_threshold,
        "chosen_alert_threshold": settings.risk_alert_threshold,
        "manual_validation": calibration_guardrail,
        "calibration_guardrail": calibration_guardrail,
        "independent_manual_holdout": manual_holdout,
        "warnings": warnings,
    }

    phishing_path = model_dir / "phishing_xgb.joblib"
    anomaly_path = model_dir / "anomaly_iforest.joblib"
    joblib.dump(classifier, phishing_path)
    joblib.dump(anomaly, anomaly_path)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def _print_summary(metrics: dict[str, Any], model_dir: Path, metrics_path: Path) -> None:
    if metrics["warnings"]:
        for warning in metrics["warnings"]:
            print(f"WARNING: {warning}")
    print("Training complete")
    print(f"Dataset: {metrics['dataset_path']} ({metrics['dataset_type']})")
    print(f"Usable rows: {metrics['usable_rows']}")
    print(f"Phishing/benign rows: {metrics['phishing_rows']}/{metrics['benign_rows']}")
    print(f"Accuracy: {metrics['accuracy']}")
    print(f"Precision: {metrics['precision']}")
    print(f"Recall: {metrics['recall']}")
    print(f"F1: {metrics['f1']}")
    print(f"ROC-AUC: {metrics['roc_auc']}")
    print(f"Saved classifier: {model_dir / 'phishing_xgb.joblib'}")
    print(f"Saved anomaly model: {model_dir / 'anomaly_iforest.joblib'}")
    print(f"Saved metrics: {metrics_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train SHANK phishing detection models.")
    parser.add_argument("--dataset", default="datasets/phishing_urls_seed.csv")
    parser.add_argument("--model-dir", default="ml/models")
    parser.add_argument("--metrics", default="ml/models/metrics.json")
    args = parser.parse_args()
    metrics = train(Path(args.dataset), Path(args.model_dir), Path(args.metrics))
    _print_summary(metrics, Path(args.model_dir), Path(args.metrics))


if __name__ == "__main__":
    main()
