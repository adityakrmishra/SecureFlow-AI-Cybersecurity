import pytest
from src.backend.ml_models.phishing_detection import PhishingDetector
from src.backend.network_analysis.packet_analyzer import PacketAnalyzer
from src.backend.threat_intel.intel_processor import ThreatIntelProcessor

@pytest.fixture
def components():
    return {
        "phish_detector": PhishingDetector(),
        "packet_analyzer": PacketAnalyzer(),
        "intel_processor": ThreatIntelProcessor()
    }

@pytest.mark.parametrize("url, expected", [
    ("http://paypal-security.com/login", 1),
    ("https://github.com/security", 0),
    ("http://192.168.1.1:8080/reset", 1)
])
def test_phishing_network_integration(components, url, expected):
    # Test phishing detection
    phish_result = components["phish_detector"].predict(url, "")
    
    # Test network analysis
    packet_data = {"src_ip": "192.168.1.100", "dst_ip": url.split('/')[2]}
    network_result = components["packet_analyzer"]._check_malicious_ip(packet_data["dst_ip"])
    
    assert phish_result["verdict"] == expected
    assert (network_result["suspicious_ips"].get(packet_data["dst_ip"], 0) == expected

def test_threat_scoring(components):
    ioc = {"type": "IP", "value": "94.130.14.15"}
    score = components["intel_processor"].score_threat(ioc)
    assert 0 <= score <= 1

def test_invalid_input_handling(components):
    with pytest.raises(ValueError):
        components["phish_detector"].predict(None, "")
    
    with pytest.raises(TypeError):
        components["intel_processor"].process_iocs("invalid")

def test_siem_alert_trigger(components, mocker):
    mock_post = mocker.patch('requests.post')
    test_ioc = {"value": "malicious-domain.xyz", "score": 0.9}
    components["intel_processor"]._send_to_siem(test_ioc)
    mock_post.assert_called_once()
