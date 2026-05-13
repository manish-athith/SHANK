# Model Performance

Models are generated from runtime-compatible URL features. The trainer reads the URL column, runs the same SHANK feature extractor used by `/api/v1/predict-url`, and saves:

- `ml/models/phishing_xgb.joblib`
- `ml/models/anomaly_iforest.joblib`
- `ml/models/metrics.json`

The repository seed dataset has only 20 rows and is smoke-test-only:

```powershell
$env:PYTHONPATH="$PWD\backend;$PWD"
python -m ml.training.train --dataset datasets/phishing_urls_seed.csv --model-dir ml/models --metrics ml/models/metrics.json
```

For the larger PhiUSIIL phishing URL dataset:

```powershell
py -3.11 -m ml.training.train --dataset datasets/phiusiil_phishing_urls.csv --model-dir ml/models --metrics ml/models/metrics.json
py -3.11 scripts/evaluate_manual_urls.py
```

Inside Docker:

```powershell
docker compose exec backend python -m ml.training.train --dataset datasets/phiusiil_phishing_urls.csv --model-dir ml/models --metrics ml/models/metrics.json
docker compose exec backend python /app/scripts/evaluate_manual_urls.py
docker compose restart backend stream-processor
```

PhiUSIIL columns are interpreted as:

- `URL`: URL to featurize.
- `label`: source label, where `0` means phishing and `1` means legitimate.
- SHANK target label: source `0 -> 1` phishing, source `1 -> 0` benign.

The trainer ignores PhiUSIIL precomputed columns because they are not available during runtime prediction.

Calibration uses a held-out PhiUSIIL validation split plus `datasets/manual_validation_urls.csv` as a calibration guardrail. `datasets/manual_holdout_urls.csv` is evaluated separately and is not used for calibration. The holdout includes real-world benign commercial, enterprise, developer, banking, and security URLs plus synthetic phishing-style URLs on reserved example domains.

These metrics are split by purpose:

- Training metrics: model behavior on the PhiUSIIL train/test split.
- Calibration guardrail: examples used to reduce obvious URL-only false positives.
- Independent manual holdout: regression check for real-world benign URLs and synthetic impersonation URLs not used for calibration.

SHANK remains URL-feature-only. It does not inspect live page content, certificates, DNS age, redirects, or external reputation during training. Treat release artifacts as demo/research artifacts, not production proof.

Metrics written to `ml/models/metrics.json`:

- accuracy
- precision
- recall
- F1 score
- ROC-AUC
- confusion matrix as `[[true_benign, false_positive], [false_negative, true_phishing]]`
- false positive and false negative counts
- classification report for benign and phishing classes
- feature list used by both training and inference
- dataset metadata, including row counts, label mapping, and training timestamp
- calibration method, chosen probability threshold, and configured alert threshold
- calibration guardrail and independent manual holdout summaries when those files exist
- warnings for small datasets, class imbalance, or suspiciously perfect ROC-AUC

Phishing is the positive class for precision, recall, F1, ROC-AUC, and false negative counts. Higher `phishing_probability` still means higher phishing risk in API responses.

The dashboard displays alert timestamps in the browser's local time. Backend timestamps without explicit timezone suffixes are normalized as UTC before rendering.
