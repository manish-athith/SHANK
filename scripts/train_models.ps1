param(
    [string]$Dataset = "datasets/phiusiil_phishing_urls.csv",
    [string]$ModelDir = "ml/models",
    [string]$Metrics = "ml/models/metrics.json"
)
$ErrorActionPreference = "Stop"
$env:PYTHONPATH = "$PWD\backend;$PWD"
py -3.11 -m ml.training.train --dataset $Dataset --model-dir $ModelDir --metrics $Metrics
