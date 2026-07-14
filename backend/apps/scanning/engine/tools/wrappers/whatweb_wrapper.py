"""WhatWeb — Web technology fingerprinting."""
from __future__ import annotations
import json
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class WhatWebTool(ExternalTool):
    name = 'whatweb'
    binary = 'whatweb'
    capabilities = [ToolCapability.RECON]
    default_timeout = 120

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        aggression = options.get('aggression', 1)
        args = [self.binary, target, '--log-json=/dev/stdout', f'-a{aggression}']
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        for line in raw.strip().splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            target = obj.get('target', '')
            plugins = obj.get('plugins', {})
            techs = []
            for name, detail in plugins.items():
                version = detail.get('version', [''])[0] if isinstance(detail.get('version'), list) else ''
                techs.append(f'{name} {version}'.strip())
            if techs:
                results.append(ToolResult(
                    tool_name=self.name,
                    category='tech_detection',
                    title=f'Technologies on {target}',
                    description=', '.join(techs),
                    severity=ToolSeverity.INFO,
                    confidence=0.80,
                    url=target,
                    metadata={'technologies': techs, 'plugins': list(plugins.keys())},
                ))
        return results

TOOL_CLASS = WhatWebTool
