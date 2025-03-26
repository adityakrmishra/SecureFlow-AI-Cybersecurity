import pytest
from unittest import mock
from src.backend.automation.response_engine import ResponseEngine

@pytest.fixture
def engine():
    return ResponseEngine(playbook_dir="tests/data/playbooks")

@pytest.mark.parametrize("alert, expected_actions", [
    ({"triggers": ["ransomware"], "source_ip": "10.0.0.5"}, 
    ["isolate_host", "block_ioc"]),
    
    ({"triggers": ["phishing"], "url": "malicious.site"}, 
    ["block_url", "alert_soc"])
])
def test_playbook_execution(engine, alert, expected_actions):
    with mock.patch.object(engine, '_execute_action') as mock_execute:
        engine.handle_alert(alert)
        executed_actions = [call.args[0]['name'] for call in mock_execute.call_args_list]
        assert set(executed_actions) == set(expected_actions)

def test_parameter_templating(engine):
    alert = {"src_ip": "192.168.1.100", "ioc": "badhash123"}
    action = {
        "name": "block_ioc",
        "parameters": {"target": "{src_ip}", "hash": "{ioc}"}
    }
    resolved = engine._resolve_params(action["parameters"], alert)
    assert resolved["target"] == alert["src_ip"]
    assert resolved["hash"] == alert["ioc"]

def test_invalid_playbook_handling(engine, caplog):
    alert = {"triggers": ["invalid_trigger"]}
    engine.handle_alert(alert)
    assert "No matching playbooks" in caplog.text

def test_action_error_handling(engine, mocker):
    mocker.patch.object(engine, '_isolate_host', side_effect=Exception("Failed"))
    alert = {"triggers": ["ransomware"], "source_ip": "10.0.0.6"}
    
    with pytest.raises(Exception, match="Failed"):
        engine.handle_alert(alert)
