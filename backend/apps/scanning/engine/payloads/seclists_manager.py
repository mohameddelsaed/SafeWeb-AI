"""
SecLists Manager — Download, index, and serve payloads from the SecLists
repository (https://github.com/danielmiessler/SecLists).

Manages:
  - Cloning / updating the SecLists repo
  - Indexing payload files by category (fuzzing, discovery, passwords, etc.)
  - Smart payload selection based on scan context (tech, depth, WAF)
  - Memory-efficient lazy file reading with line-count caching
"""
from __future__ import annotations

import logging
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

# Default install location — relative to the engine package
_DEFAULT_SECLISTS_DIR = Path(__file__).resolve().parent.parent / 'payloads' / 'data' / 'seclists'

# Git clone URL
_SECLISTS_REPO = 'https://github.com/danielmiessler/SecLists.git'

# Category → subdirectory mapping
SECLISTS_CATEGORIES = {
    'discovery_web':     'Discovery/Web-Content',
    'discovery_dns':     'Discovery/DNS',
    'discovery_infra':   'Discovery/Infrastructure',
    'fuzzing':           'Fuzzing',
    'passwords':         'Passwords',
    'usernames':         'Usernames',
    'sqli':              'Fuzzing/SQLi',
    'xss':               'Fuzzing/XSS',
    'lfi':               'Fuzzing/LFI',
    'xxe':               'Fuzzing/XXE-Fuzzing',
    'ssrf':              'Fuzzing/SSRF',
    'command_injection': 'Fuzzing/command-injection-commix.txt',
    'traversal':         'Fuzzing/LFI/LFI-Jhaddix.txt',
    'idor':              'Fuzzing/IDOR',
    'ssti':              'Fuzzing/template-engines-special-vars.txt',
    'default_creds':     'Passwords/Default-Credentials',
    'common_passwords':  'Passwords/Common-Credentials',
    'raft_dirs':         'Discovery/Web-Content/raft-medium-directories.txt',
    'raft_files':        'Discovery/Web-Content/raft-medium-files.txt',
    'api_paths':         'Discovery/Web-Content/api',
    'backup_files':      'Discovery/Web-Content/backup-file.txt',
}


class SecListsManager:
    """Manages SecLists repo on disk — clone, update, index, and serve payloads."""

    def __init__(self, base_dir: str | Path | None = None):
        self.base_dir = Path(base_dir) if base_dir else _DEFAULT_SECLISTS_DIR
        self._index_cache: dict[str, list[Path]] = {}

    # ── Lifecycle ─────────────────────────────────────────────────────────

    @property
    def is_installed(self) -> bool:
        return (self.base_dir / 'Discovery').is_dir()

    def install(self, shallow: bool = True) -> bool:
        """Clone SecLists repository.  Returns True on success."""
        if self.is_installed:
            logger.info('SecLists already installed at %s', self.base_dir)
            return True
        self.base_dir.parent.mkdir(parents=True, exist_ok=True)
        args = ['git', 'clone']
        if shallow:
            args += ['--depth', '1']
        args += [_SECLISTS_REPO, str(self.base_dir)]
        logger.info('Cloning SecLists → %s', self.base_dir)
        try:
            subprocess.run(args, check=True, capture_output=True, timeout=600)
            logger.info('SecLists installed successfully')
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error('Failed to clone SecLists: %s', e)
            return False

    def update(self) -> bool:
        """Pull latest changes."""
        if not self.is_installed:
            return self.install()
        try:
            subprocess.run(
                ['git', 'pull', '--ff-only'],
                cwd=str(self.base_dir),
                check=True, capture_output=True, timeout=120,
            )
            self._index_cache.clear()
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            return False

    # ── Indexing ──────────────────────────────────────────────────────────

    def list_files(self, category: str) -> list[Path]:
        """List all payload files for a SecLists category."""
        if category in self._index_cache:
            return self._index_cache[category]

        subpath = SECLISTS_CATEGORIES.get(category, category)
        target = self.base_dir / subpath

        if target.is_file():
            files = [target]
        elif target.is_dir():
            files = sorted(
                p for p in target.rglob('*.txt')
                if p.stat().st_size > 0 and not p.name.startswith('.')
            )
        else:
            files = []

        self._index_cache[category] = files
        return files

    def get_file(self, category: str, name: str | None = None) -> Path | None:
        """Get a specific payload file by category and optional name filter."""
        files = self.list_files(category)
        if not files:
            return None
        if name:
            name_lower = name.lower()
            for f in files:
                if name_lower in f.stem.lower():
                    return f
        return files[0]

    # ── Payload reading ───────────────────────────────────────────────────

    def read_payloads(self, category: str, name: str | None = None,
                      max_lines: int = 0) -> list[str]:
        """Read payloads from a SecLists file. Returns list of non-empty lines."""
        filepath = self.get_file(category, name)
        if not filepath or not filepath.exists():
            return []
        return list(self._iter_lines(filepath, max_lines))

    def iter_payloads(self, category: str, name: str | None = None,
                      max_lines: int = 0) -> Iterator[str]:
        """Lazily iterate over payload lines."""
        filepath = self.get_file(category, name)
        if filepath and filepath.exists():
            yield from self._iter_lines(filepath, max_lines)

    def _iter_lines(self, path: Path, max_lines: int = 0) -> Iterator[str]:
        """Read lines from file, stripping comments and blanks."""
        count = 0
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        yield line
                        count += 1
                        if max_lines and count >= max_lines:
                            break
        except OSError as e:
            logger.warning('Cannot read %s: %s', path, e)

    @lru_cache(maxsize=128)
    def line_count(self, filepath: str) -> int:
        """Count non-empty, non-comment lines in a file."""
        p = Path(filepath)
        if not p.exists():
            return 0
        count = 0
        try:
            with open(p, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        count += 1
        except OSError:
            pass
        return count

    # ── Smart selection ───────────────────────────────────────────────────

    def get_payloads_for_context(self, vuln_type: str, tech_stack: str = '',
                                 depth: str = 'medium',
                                 max_payloads: int = 500) -> list[str]:
        """Select best payload file based on scan context.

        Args:
            vuln_type: e.g. 'sqli', 'xss', 'lfi', 'discovery_web'
            tech_stack: e.g. 'php', 'java', 'aspnet'
            depth: 'quick' | 'medium' | 'deep'
            max_payloads: cap number of payloads returned
        """
        category = vuln_type.lower()
        files = self.list_files(category)
        if not files:
            # Fallback: try fuzzing category
            files = self.list_files('fuzzing')
            files = [f for f in files if category in f.stem.lower()]

        if not files:
            return []

        # Score and pick best file for context
        best_file = files[0]
        best_score = -1
        for f in files:
            score = 0
            fname = f.stem.lower()
            if tech_stack and tech_stack.lower() in fname:
                score += 10
            if depth == 'quick' and ('small' in fname or 'short' in fname or 'top' in fname):
                score += 5
            elif depth == 'deep' and ('large' in fname or 'big' in fname or 'full' in fname):
                score += 5
            elif depth == 'medium' and ('medium' in fname or 'common' in fname):
                score += 5
            fsize = f.stat().st_size
            if depth == 'quick' and fsize < 50000:
                score += 3
            elif depth == 'deep' and fsize > 100000:
                score += 3
            if score > best_score:
                best_score = score
                best_file = f

        lines = max_payloads or (100 if depth == 'quick' else 500 if depth == 'medium' else 0)
        return list(self._iter_lines(best_file, lines))

    def summary(self) -> dict[str, int]:
        """Return {category: file_count} for all known categories."""
        return {cat: len(self.list_files(cat)) for cat in SECLISTS_CATEGORIES}
