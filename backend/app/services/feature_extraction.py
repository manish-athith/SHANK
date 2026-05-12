from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "bank",
    "wallet",
    "password",
    "confirm",
    "invoice",
    "urgent",
    "limited",
    "support",
}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def extract_domain(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.hostname.lower() if parsed.hostname else None


def _count_digits(value: str) -> int:
    return sum(char.isdigit() for char in value)


@dataclass(frozen=True)
class URLFeatures:
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    entropy: float
    digit_count: int
    dot_count: int
    hyphen_count: int
    slash_count: int
    at_symbol: int
    ip_hostname: int
    https: int
    suspicious_keyword_count: int
    query_param_count: int
    subdomain_count: int

    def as_dict(self) -> dict[str, float]:
        return {key: float(value) for key, value in self.__dict__.items()}


class FeatureExtractor:
    feature_order = [
        "url_length",
        "hostname_length",
        "path_length",
        "query_length",
        "entropy",
        "digit_count",
        "dot_count",
        "hyphen_count",
        "slash_count",
        "at_symbol",
        "ip_hostname",
        "https",
        "suspicious_keyword_count",
        "query_param_count",
        "subdomain_count",
        "spf_pass",
        "dkim_pass",
        "attachment_count",
        "executable_attachment_count",
    ]

    def extract_url(self, url: str | None) -> dict[str, float]:
        value = url or ""
        parsed = urlparse(value if "://" in value else f"http://{value}")
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        lower_url = value.lower()
        ip_hostname = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname))
        features = URLFeatures(
            url_length=len(value),
            hostname_length=len(hostname),
            path_length=len(path),
            query_length=len(query),
            entropy=shannon_entropy(value),
            digit_count=_count_digits(value),
            dot_count=value.count("."),
            hyphen_count=value.count("-"),
            slash_count=value.count("/"),
            at_symbol=int("@" in value),
            ip_hostname=int(ip_hostname),
            https=int(parsed.scheme == "https"),
            suspicious_keyword_count=sum(keyword in lower_url for keyword in SUSPICIOUS_KEYWORDS),
            query_param_count=len(parse_qs(query)),
            subdomain_count=max(hostname.count(".") - 1, 0),
        )
        return features.as_dict()

    def extract_email(self, event: dict[str, Any]) -> dict[str, float]:
        headers = event.get("headers") or {}
        attachments = event.get("attachments") or []
        auth_results = str(headers.get("Authentication-Results", "")).lower()
        executable_ext = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".iso")
        executable_count = sum(
            str(item.get("filename", "")).lower().endswith(executable_ext) for item in attachments
        )
        return {
            "spf_pass": float("spf=pass" in auth_results),
            "dkim_pass": float("dkim=pass" in auth_results),
            "attachment_count": float(len(attachments)),
            "executable_attachment_count": float(executable_count),
        }

    def extract(self, event: dict[str, Any]) -> dict[str, float]:
        features = self.extract_url(event.get("url"))
        features.update(self.extract_email(event))
        for key in self.feature_order:
            features.setdefault(key, 0.0)
        return features

    def vectorize(self, features: dict[str, float]) -> list[float]:
        return [float(features.get(key, 0.0)) for key in self.feature_order]

