"""Wappalyzer shim — Technology detection via webtech backend."""
from __future__ import annotations
import json
from typing import Any
from ..base import ExternalTool, ToolCapability
from ..result import ToolResult, ToolSeverity


class WappalyzerTool(ExternalTool):
    name = 'wappalyzer'
    binary = 'wappalyzer'
    capabilities = [ToolCapability.RECON]
    default_timeout = 120

    def run(self, target: str, **options: Any) -> list[ToolResult]:
        if not self.is_available():
            return []
        args = [self.binary, target]
        raw = self._exec(args)
        return self.parse_output(raw)

    def parse_output(self, raw: str) -> list[ToolResult]:
        results = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return results
        # Support both webtech format {"techs": [...]} and legacy {"technologies": [...]}
        if isinstance(data, dict):
            techs = data.get('techs', data.get('technologies', []))
        elif isinstance(data, list):
            techs = data
        else:
            techs = []
        for t in techs:
            if isinstance(t, dict):
                name = t.get('name', '')
                version = t.get('version', '')
                cats = t.get('categories', [])
                if isinstance(cats, list) and cats and isinstance(cats[0], dict):
                    cats = [c.get('name', '') for c in cats]
                label = f'Tech: {name}' + (f' {version}' if version else '')
            else:
                name = str(t)
                label = f'Tech: {name}'
                cats = []
            if not name:
                continue
            results.append(ToolResult(
                tool_name=self.name,
                category='tech_detection',
                title=label,
                severity=ToolSeverity.INFO,
                confidence=0.8,
                metadata={'categories': cats, 'version': version if isinstance(t, dict) else ''},
            ))
        return results

TOOL_CLASS = WappalyzerTool
