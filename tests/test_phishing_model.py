import pytest
import numpy as np
from src.backend.ml_models.phishing_detection import PhishingDetector

@pytest.fixture(scope="module")
def detector():
    return PhishingDetector()

def test_model_loading(detector):
    assert detector.model is not None
    assert detector.tokenizer is not None

@pytest.mark.parametrize("url, expected", [
    ("http://paypal-update.xyz/login", 1),
    ("https://github.com/security", 0),
    ("https://legit-bank.com?query=1", 0),
    ("http://192.168.1.1:8080/reset", 1)
])
def test_url_prediction(detector, url, expected):
    pred = detector.predict(url, "")
    assert pred['verdict'] == expected

def test_feature_engineering(detector):
    features = detector._extract_url_features("http://phish.com")
    assert features['num_subdomains'] == 1
    assert features['has_ip'] == 0

def test_invalid_input(detector):
    with pytest.raises(ValueError):
        detector.predict(None, "")
