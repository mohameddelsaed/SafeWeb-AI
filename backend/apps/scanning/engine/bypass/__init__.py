"""
Phase 28 — 403/401 Bypass Engine.

Automated bypass techniques for HTTP 403 Forbidden and 401 Unauthorized responses.
Inspired by nomore403 and Forbidden-Buster.

Modules:
  - forbidden_bypass: Core bypass engine with path, method, header, and protocol techniques.
"""

from .forbidden_bypass import ForbiddenBypassEngine

__all__ = ['ForbiddenBypassEngine']
