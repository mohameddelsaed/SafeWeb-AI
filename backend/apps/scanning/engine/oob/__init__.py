"""
Out-of-Band (OOB) Callback Infrastructure.

Provides blind vulnerability detection via external callback correlation.
Supports Interactsh integration, unique callback URL generation, and
payload-to-callback mapping for blind SQLi, SSRF, XXE, RCE, and SSTI.
"""
from .oob_manager import OOBManager
from .interactsh_client import InteractshClient
from .callback_server import CallbackServer

__all__ = ['OOBManager', 'InteractshClient', 'CallbackServer']
