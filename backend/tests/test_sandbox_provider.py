import pytest
from apps.scanning.engine.sandbox import AsyncSSHSandboxProvider, LocalMockSandboxProvider

@pytest.mark.unit
def test_sandbox_whoami_execution():
    provider = LocalMockSandboxProvider()
    code, stdout, stderr = provider.execute_command_sync("whoami")
    assert code == 0
    assert "sandbox" in stdout.lower() or len(stdout) > 0

@pytest.mark.unit
def test_async_ssh_provider_init():
    provider = AsyncSSHSandboxProvider(host="127.0.0.1", port=2222, username="sandbox", password="secret")
    assert provider.host == "127.0.0.1"
    assert provider.port == 2222
