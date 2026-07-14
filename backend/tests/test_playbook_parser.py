import pytest
from apps.scanning.engine.playbooks.parser import PlaybookParser

@pytest.mark.unit
def test_parse_web_app_quick_playbook():
    """Parse web-app-quick.yaml and verify phase timeouts and tool allowlist."""
    config = PlaybookParser.load_playbook("web-app-quick")
    assert config["profile_id"] == "web-app-quick"
    assert config["phase_timeouts"]["recon"] == 300
    assert "nuclei" in config["tool_allowlist"]
    assert config["max_cost_usd"] == 5.0
