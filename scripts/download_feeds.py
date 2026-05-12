from __future__ import annotations

import argparse
import csv
from pathlib import Path

import httpx


FEEDS = {
    "openphish": "https://openphish.com/feed.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "phishtank": "https://data.phishtank.com/data/online-valid.csv",
}


def download(url: str, destination: Path) -> bool:
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with httpx.stream("GET", url, timeout=60, follow_redirects=True) as response:
            response.raise_for_status()
            with destination.open("wb") as handle:
                for chunk in response.iter_bytes():
                    handle.write(chunk)
        print(f"Downloaded {url} -> {destination}")
        return True
    except httpx.HTTPError as exc:
        print(f"Warning: failed to download {url}: {exc}")
        return False


def build_training_csv(seed_file: Path, downloaded_dir: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    rows: list[tuple[str, int]] = []
    if seed_file.exists():
        with seed_file.open(newline="", encoding="utf-8") as handle:
            rows.extend((row["url"], int(row["label"])) for row in csv.DictReader(handle))

    openphish = downloaded_dir / "openphish.txt"
    if openphish.exists():
        rows.extend((line.strip(), 1) for line in openphish.read_text(encoding="utf-8").splitlines() if line.strip())

    urlhaus = downloaded_dir / "urlhaus.csv"
    if urlhaus.exists():
        for line in urlhaus.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("#") or not line.strip():
                continue
            try:
                parts = next(csv.reader([line]))
                if len(parts) > 2:
                    rows.append((parts[2], 1))
            except csv.Error as exc:
                print(f"Warning: skipped malformed URLHaus row: {exc}")

    phishtank = downloaded_dir / "phishtank.csv"
    if phishtank.exists():
        with phishtank.open(newline="", encoding="utf-8", errors="ignore") as handle:
            for row in csv.DictReader(handle):
                url = row.get("url")
                if url:
                    rows.append((url, 1))

    seen: set[str] = set()
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["url", "label"])
        for url, label in rows:
            if url not in seen:
                writer.writerow([url, label])
                seen.add(url)


def main() -> None:
    parser = argparse.ArgumentParser(description="Download real phishing feeds for SHANK model training.")
    parser.add_argument("--out", default="datasets/downloaded")
    parser.add_argument("--training-csv", default="datasets/phishing_urls_training.csv")
    args = parser.parse_args()

    out = Path(args.out)
    for name, url in FEEDS.items():
        suffix = "txt" if name == "openphish" else "csv"
        download(url, out / f"{name}.{suffix}")
    build_training_csv(Path("datasets/phishing_urls_seed.csv"), out, Path(args.training_csv))
    print(f"Wrote {args.training_csv}")


if __name__ == "__main__":
    main()
