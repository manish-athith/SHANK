$ErrorActionPreference = "Stop"
$env:PYTHONPATH = "$PWD\backend;$PWD"
python -m ml.training.train --dataset datasets/phishing_urls_seed.csv --model-dir ml/models --metrics ml/models/metrics.json

