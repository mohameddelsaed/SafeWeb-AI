import os
import glob
from typing import Optional

def load_skill_markdown(tag: str) -> Optional[str]:
    """Load matching skill markdown content based on vulnerability tags."""
    skills_dir = os.path.join(os.path.dirname(__file__), 'skills')
    if not os.path.exists(skills_dir):
        return None
        
    tag_lower = tag.lower()
    for file_path in glob.glob(os.path.join(skills_dir, '*.md')):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                if tag_lower in content.lower() or tag_lower in os.path.basename(file_path).lower():
                    return content
        except Exception:
            continue
    return None
