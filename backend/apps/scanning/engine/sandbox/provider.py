import os
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

class SandboxProvider(ABC):
    """Abstract base class for sandbox tool execution providers."""
    
    @abstractmethod
    async def execute_command(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Execute shell command in sandbox and return (exit_code, stdout, stderr)."""
        pass

    def execute_command_sync(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Synchronous wrapper for Celery threads."""
        try:
            return asyncio.run(self.execute_command(command, timeout))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self.execute_command(command, timeout))
            finally:
                loop.close()


class AsyncSSHSandboxProvider(SandboxProvider):
    """Execution provider communicating with ephemeral Docker sandbox via AsyncSSH."""
    
    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None
    ):
        self.host = host or os.getenv('SANDBOX_HOST', 'localhost')
        self.port = int(port or os.getenv('SANDBOX_PORT', 2222))
        self.username = username or os.getenv('SANDBOX_USER', 'sandbox')
        self.password = password or os.getenv('SANDBOX_PASSWORD', 'sandbox_secret_key_2026')

    async def execute_command(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        import asyncssh
        try:
            async with asyncssh.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                known_hosts=None
            ) as conn:
                result = await asyncio.wait_for(conn.run(command), timeout=timeout)
                return (result.exit_status or 0, result.stdout or "", result.stderr or "")
        except asyncio.TimeoutError:
            logger.error(f"Sandbox command timed out after {timeout}s: {command}")
            return (-1, "", f"Execution timed out after {timeout} seconds.")
        except Exception as e:
            logger.error(f"Sandbox execution error: {str(e)}")
            return (-2, "", f"Sandbox execution failure: {str(e)}")


class LocalMockSandboxProvider(SandboxProvider):
    """Fallback / testing provider executing commands locally or returning mocks."""
    
    async def execute_command(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        if command.strip() == "whoami":
            return (0, "sandbox\n", "")
        # Safe command execution via asyncio subprocess
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return (proc.returncode or 0, stdout.decode('utf-8', errors='ignore'), stderr.decode('utf-8', errors='ignore'))
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return (-1, "", "Execution timed out.")
