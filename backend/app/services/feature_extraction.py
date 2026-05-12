from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse

import pandas as pd


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

BRAND_KEYWORDS = {
    "adobe",
    "amazon",
    "apple",
    "bankofamerica",
    "cloudflare",
    "docker",
    "dropbox",
    "facebook",
    "fastapi",
    "github",
    "google",
    "linkedin",
    "microsoft",
    "microsoftonline",
    "mozilla",
    "netflix",
    "npmjs",
    "paypal",
    "postgresql",
    "pypi",
    "reddit",
    "redis",
    "stackoverflow",
    "virustotal",
    "wikipedia",
}

KNOWN_URL_SHORTENERS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "s.id",
    "t.co",
    "tinyurl.com",
}

KNOWN_BRAND_REGISTERED_DOMAINS = {
    "amazon.com",
    "apple.com",
    "cloudflare.com",
    "docker.com",
    "fastapi.tiangolo.com",
    "github.com",
    "google.com",
    "kubernetes.io",
    "linkedin.com",
    "microsoft.com",
    "mozilla.org",
    "npmjs.com",
    "postgresql.org",
    "pypi.org",
    "python.org",
    "reddit.com",
    "redis.io",
    "stackoverflow.com",
    "virustotal.com",
    "wikipedia.org",
}

SUSPICIOUS_TLDS = {
    "biz",
    "click",
    "cn",
    "info",
    "ru",
    "tk",
    "top",
    "xyz",
}

COMMON_SECOND_LEVEL_TLDS = {"co", "com", "net", "org", "gov", "ac", "edu"}


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


def registered_domain(hostname: str | None) -> str:
    if not hostname:
        return ""
    parts = [part for part in hostname.lower().strip(".").split(".") if part]
    if len(parts) < 2:
        return hostname.lower()
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in COMMON_SECOND_LEVEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _tokens(value: str) -> list[str]:
    return [token for token in re.split(r"[^a-z0-9]+", value.lower()) if token]


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
    registered_domain_length: int
    tld_length: int
    suspicious_tld: int
    brand_keyword_count: int
    domain_contains_brand_keyword: int
    brand_keyword_not_in_registered_domain: int
    known_brand_registered_domain: int
    brand_in_subdomain: int
    hostname_is_registered_domain: int
    known_url_shortener: int
    path_token_count: int
    repeated_separator_count: int
    has_login_keyword: int
    has_verify_keyword: int
    has_account_keyword: int
    has_password_keyword: int

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
        "registered_domain_length",
        "tld_length",
        "suspicious_tld",
        "brand_keyword_count",
        "domain_contains_brand_keyword",
        "brand_keyword_not_in_registered_domain",
        "known_brand_registered_domain",
        "brand_in_subdomain",
        "hostname_is_registered_domain",
        "known_url_shortener",
        "path_token_count",
        "repeated_separator_count",
        "has_login_keyword",
        "has_verify_keyword",
        "has_account_keyword",
        "has_password_keyword",
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
        lower_hostname = hostname.lower()
        reg_domain = registered_domain(hostname)
        tld = reg_domain.rsplit(".", 1)[-1] if "." in reg_domain else ""
        brand_count = sum(keyword in lower_url for keyword in BRAND_KEYWORDS)
        domain_brand_count = sum(keyword in lower_hostname for keyword in BRAND_KEYWORDS)
        reg_domain_brand_count = sum(keyword in reg_domain for keyword in BRAND_KEYWORDS)
        subdomain_part = lower_hostname.removesuffix(reg_domain).rstrip(".")
        path_tokens = _tokens(path)
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
            registered_domain_length=len(reg_domain),
            tld_length=len(tld),
            suspicious_tld=int(tld in SUSPICIOUS_TLDS),
            brand_keyword_count=brand_count,
            domain_contains_brand_keyword=int(domain_brand_count > 0),
            brand_keyword_not_in_registered_domain=int(domain_brand_count > 0 and reg_domain_brand_count == 0),
            known_brand_registered_domain=int(
                reg_domain in KNOWN_BRAND_REGISTERED_DOMAINS
                or lower_hostname in KNOWN_BRAND_REGISTERED_DOMAINS
            ),
            brand_in_subdomain=int(any(keyword in subdomain_part for keyword in BRAND_KEYWORDS)),
            hostname_is_registered_domain=int(lower_hostname == reg_domain or lower_hostname == f"www.{reg_domain}"),
            known_url_shortener=int(reg_domain in KNOWN_URL_SHORTENERS),
            path_token_count=len(path_tokens),
            repeated_separator_count=len(re.findall(r"[-_/]{2,}", value)),
            has_login_keyword=int("login" in lower_url or "signin" in lower_url),
            has_verify_keyword=int("verify" in lower_url),
            has_account_keyword=int("account" in lower_url),
            has_password_keyword=int("password" in lower_url),
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

    def to_frame(self, features: dict[str, float] | list[dict[str, float]]) -> pd.DataFrame:
        rows = features if isinstance(features, list) else [features]
        return pd.DataFrame(
            [[float(row.get(key, 0.0)) for key in self.feature_order] for row in rows],
            columns=self.feature_order,
        )
