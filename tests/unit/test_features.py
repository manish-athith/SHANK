from app.services.feature_extraction import FeatureExtractor, extract_domain, shannon_entropy


def test_extract_domain_normalizes_hostname():
    assert extract_domain("HTTPS://Login.Example.COM/path") == "login.example.com"


def test_url_features_capture_phishing_signals():
    extractor = FeatureExtractor()
    features = extractor.extract(
        {
            "url": "http://192.168.1.4/secure-login/verify?token=123456",
            "headers": {"Authentication-Results": "spf=fail dkim=fail"},
            "attachments": [{"filename": "invoice.js"}],
        }
    )

    assert features["ip_hostname"] == 1.0
    assert features["https"] == 0.0
    assert features["suspicious_keyword_count"] >= 2
    assert features["executable_attachment_count"] == 1.0
    assert len(extractor.vectorize(features)) == len(extractor.feature_order)


def test_entropy_is_positive_for_non_empty_value():
    assert shannon_entropy("abc123") > 0


def test_legitimate_registered_brand_domain_features():
    features = FeatureExtractor().extract({"url": "https://www.paypal.com/in/home"})

    assert features["is_known_legitimate_registered_domain"] == 1.0
    assert features["brand_in_registered_domain"] == 1.0
    assert features["brand_keyword_not_in_registered_domain"] == 0.0
    assert features["brand_impersonation_score"] == 0.0


def test_fake_brand_impersonation_features():
    features = FeatureExtractor().extract(
        {"url": "http://paypal-login-security-check.example.com/update-password"}
    )

    assert features["is_known_legitimate_registered_domain"] == 0.0
    assert features["brand_keyword_not_in_registered_domain"] == 1.0
    assert features["brand_in_subdomain"] == 1.0
    assert features["brand_impersonation_score"] >= 2.0
    assert features["credential_keyword_count"] >= 2.0
