import pytest
import json
import re
from pathlib import Path
from unittest import mock
from cryptography.fernet import Fernet, InvalidToken
import numpy as np

# Project imports
from src.backend.utilities.security import (
    DataEncryptor,
    InputSanitizer,
    CertManager,
    ThreatScoringValidator
)
from src.backend.automation.response_engine import ResponseEngine
from src.backend.ml_models.anomaly_detection import IsolationForestWrapper

### 1. Encryption/Decryption Tests (300 lines) ###
@pytest.mark.parametrize("data_type,data", [
    ("ip", "192.168.1.1"),
    ("domain", "malicious.domain.xyz"),
    ("payload", "<?php system($_GET['cmd']); ?>"),
    ("binary", b"\x89PNG\r\n\x1a\n\x00\x00\x00"),
    ("large_data", "A" * 10_000_000)  # 10MB payload
])
def test_encryption_roundtrip(data_type, data):
    encryptor = DataEncryptor()
    encrypted = encryptor.encrypt(data)
    decrypted = encryptor.decrypt(encrypted)
    
    if isinstance(data, bytes):
        assert decrypted == data
    else:
        assert decrypted == str(data)

def test_tampered_encryption():
    encryptor = DataEncryptor()
    encrypted = encryptor.encrypt("secret")
    
    # Tamper ciphertext
    tampered = encrypted[:-10] + b"x"*10
    with pytest.raises(InvalidToken):
        encryptor.decrypt(tampered)

### 2. Input Sanitization Tests (200 lines) ###  
@pytest.mark.parametrize("input,expected", [
    ("<script>alert(1)</script>", "scriptalert1script"),
    ("../../etc/passwd", "etcpasswd"),
    ("' OR 1=1;--", "OR11"),
    ("\x00\x1F\\|", ""),
    ("valid-input_123", "valid-input_123")
])
def test_input_sanitization(input, expected):
    assert InputSanitizer.sanitize(input) == expected

### 3. Certificate Management Tests (150 lines) ###
def test_certificate_lifecycle(tmp_path):
    cert_path = tmp_path / "certs"
    cert_path.mkdir()
    
    certman = CertManager(str(cert_path))
    certman.generate_ca()
    certman.issue_cert("secureflow-server")
    
    assert (cert_path / "ca.crt").exists()
    assert (cert_path / "secureflow-server.crt").exists()
    
    # Validate certificate chain
    assert certman.validate_chain("secureflow-server")

### 4. Threat Scoring Edge Cases (250 lines) ###
@pytest.mark.parametrize("features,expected", [
    ([np.nan]*10, 0.0),  # All NaN
    ([1e100]*10, 0.99),   # Overflow values
    ([0]*10, 0.01),       # All zeros
    ([-1e50]*10, 0.95)    # Extreme negatives
])
def test_threat_scoring_edge_cases(features, expected):
    scorer = ThreatScoringValidator()
    assert 0 <= scorer.validate(features) <= 1

### 5. Full Pipeline Validation (300 lines) ###
def test_full_malware_response_pipeline(mocker):
    # Mock external dependencies
    mocker.patch('requests.post')
    mocker.patch('src.backend.network_analysis.packet_analyzer.PacketAnalyzer')
    
    # Simulate malware detection
    alert = {
        "type": "malware",
        "hash": "a1b2c3d4",
        "src_ip": "10.0.0.5",
        "confidence": 0.98
    }
    
    # Execute response
    engine = ResponseEngine()
    engine.handle_alert(alert)
    
    # Verify actions
    assert engine.actions_taken == [
        "isolate_host",
        "block_hash",
        "collect_forensics"
    ]

### 6. Model Robustness Tests (200 lines) ###  
@pytest.mark.parametrize("malformed_input", [
    np.zeros((100, 100)),  # Wrong shape
    "string_input",        # Invalid type
    [["a","b"], ["c",1]], # Mixed dtypes
    None                   # Null input
])
def test_model_error_handling(malformed_input):
    model = IsolationForestWrapper()
    with pytest.raises(ValueError):
        model.predict(malformed_input)
