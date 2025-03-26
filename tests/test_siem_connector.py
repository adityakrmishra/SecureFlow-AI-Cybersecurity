import pytest
from unittest import mock
from src.backend.siem_integration.splunk_connector import SplunkConnector

@pytest.fixture
def splunk():
    return SplunkConnector()

def test_event_forwarding(splunk, mocker):
    mock_post = mocker.patch('requests.post')
    test_event = {"threat": "phishing", "src_ip": "10.0.0.1"}
    splunk.send_security_event(test_event, "secureflow")
    mock_post.assert_called_once()
    assert "phishing" in mock_post.call_args[1]['data']

def test_connectivity(splunk, mocker):
    mocker.patch('requests.head', return_value=Mock(status_code=200))
    assert splunk.check_connectivity() is True

def test_api_error_handling(splunk, mocker, caplog):
    mocker.patch('requests.post', side_effect=Exception("API Down"))
    splunk.send_security_event({}, "test")
    assert "Splunk HEC error" in caplog.text

def test_data_validation(splunk):
    with pytest.raises(ValidationError):
        splunk.send_security_event("invalid", "test")

def test_alert_throttling(splunk, mocker):
    mock_sleep = mocker.patch('time.sleep')
    mocker.patch('requests.post', side_effect=Exception("Rate Limited"))
    splunk.send_security_event({"alert": "test"}, "throttle_test")
    assert mock_sleep.called
