import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class PlaybookParser:
    """Parser for YAML declarative pentesting playbooks."""

    @classmethod
    def load_playbook(cls, profile_id: str) -> Dict[str, Any]:
        """Load and parse playbook configuration YAML file by profile_id."""
        base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, "configs", f"{profile_id}.yaml")
        
        if not os.path.exists(config_path):
            logger.warning(f"Playbook profile '{profile_id}' not found at {config_path}. Using default config.")
            return cls._get_default_config()

        try:
            import yaml
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                logger.info(f"Loaded playbook profile '{profile_id}': {data.get('name')}")
                return data
        except Exception as e:
            logger.error(f"Error parsing YAML playbook '{profile_id}': {str(e)}")
            return cls._get_default_config()

    @staticmethod
    def _get_default_config() -> Dict[str, Any]:
        return {
            "name": "Default Quick Profile",
            "profile_id": "default",
            "phase_timeouts": {"recon": 300, "vuln_scan": 600, "exploit": 450, "validator": 300},
            "tool_allowlist": ["subfinder", "httpx", "nuclei"],
            "max_cost_usd": 10.0
        }
