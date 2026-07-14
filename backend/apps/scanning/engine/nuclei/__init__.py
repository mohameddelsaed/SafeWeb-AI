"""
Nuclei Template Engine — Phase 20.

Integrates ProjectDiscovery's nuclei-templates ecosystem to add 12,000+
vulnerability checks covering CVEs, misconfigurations, exposed panels,
default credentials, takeovers, and technology-specific issues.
"""
from .template_manager import TemplateManager
from .template_parser import TemplateParser, NucleiTemplate
from .template_runner import TemplateRunner

__all__ = ['TemplateManager', 'TemplateParser', 'NucleiTemplate', 'TemplateRunner']
