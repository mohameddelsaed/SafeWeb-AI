"""
Ollama Client — Async / sync interface to a local Ollama LLM server.

Supports:
  - Streaming and non-streaming completions
  - JSON-mode structured output
  - Automatic model selection and fallback
  - Connection health checks
  - Prompt template rendering
  - Token budget management
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, AsyncIterator, Iterator

import aiohttp
import requests

logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = os.environ.get('OLLAMA_BASE_URL', 'http://127.0.0.1:11434')
_DEFAULT_MODEL = os.environ.get('OLLAMA_MODEL', 'llama3.1:8b')
_FALLBACK_MODELS = ['llama3.1:8b', 'llama3:8b', 'mistral:7b', 'gemma2:9b']
_DEFAULT_TIMEOUT = 120
_MAX_CONTEXT_TOKENS = 8192


class OllamaClient:
    """Client for Ollama local LLM API."""

    def __init__(self, base_url: str = '', model: str = '',
                 timeout: int = _DEFAULT_TIMEOUT):
        self.base_url = (base_url or _DEFAULT_BASE_URL).rstrip('/')
        self.model = model or _DEFAULT_MODEL
        self.timeout = timeout
        self._available: bool | None = None
        self._actual_model: str | None = None

    # ── Health / availability ─────────────────────────────────────────────

    def is_available(self) -> bool:
        """Check if Ollama server is reachable and has a usable model."""
        if self._available is not None:
            return self._available
        try:
            resp = requests.get(f'{self.base_url}/api/tags', timeout=5)
            if resp.status_code != 200:
                self._available = False
                return False
            models = [m['name'] for m in resp.json().get('models', [])]
            if self.model in models:
                self._actual_model = self.model
                self._available = True
            else:
                # Try fallbacks
                for fb in _FALLBACK_MODELS:
                    if fb in models:
                        self._actual_model = fb
                        self._available = True
                        logger.info('Ollama: using fallback model %s', fb)
                        break
                else:
                    if models:
                        self._actual_model = models[0]
                        self._available = True
                        logger.info('Ollama: using available model %s', models[0])
                    else:
                        self._available = False
        except (requests.ConnectionError, requests.Timeout):
            self._available = False
        if not self._available:
            logger.warning('Ollama not available at %s', self.base_url)
        return self._available

    def list_models(self) -> list[str]:
        """List models available on the Ollama server."""
        try:
            resp = requests.get(f'{self.base_url}/api/tags', timeout=5)
            return [m['name'] for m in resp.json().get('models', [])]
        except Exception:
            return []

    @property
    def active_model(self) -> str:
        if self._actual_model:
            return self._actual_model
        self.is_available()
        return self._actual_model or self.model

    # ── Sync API ──────────────────────────────────────────────────────────

    def generate(self, prompt: str, system: str = '',
                 temperature: float = 0.3,
                 max_tokens: int = 2048,
                 json_mode: bool = False) -> str:
        """Generate a completion (blocking). Returns the full response text."""
        if not self.is_available():
            return ''

        payload: dict[str, Any] = {
            'model': self.active_model,
            'prompt': prompt,
            'stream': False,
            'options': {
                'temperature': temperature,
                'num_predict': max_tokens,
            },
        }
        if system:
            payload['system'] = system
        if json_mode:
            payload['format'] = 'json'

        try:
            resp = requests.post(
                f'{self.base_url}/api/generate',
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json().get('response', '')
        except Exception as e:
            logger.error('Ollama generate error: %s', e)
            return ''

    def chat(self, messages: list[dict[str, str]],
             temperature: float = 0.3,
             max_tokens: int = 2048,
             json_mode: bool = False) -> str:
        """Chat completion (blocking). Returns assistant reply."""
        if not self.is_available():
            return ''

        payload: dict[str, Any] = {
            'model': self.active_model,
            'messages': messages,
            'stream': False,
            'options': {
                'temperature': temperature,
                'num_predict': max_tokens,
            },
        }
        if json_mode:
            payload['format'] = 'json'

        try:
            resp = requests.post(
                f'{self.base_url}/api/chat',
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json().get('message', {}).get('content', '')
        except Exception as e:
            logger.error('Ollama chat error: %s', e)
            return ''

    def generate_json(self, prompt: str, system: str = '',
                      temperature: float = 0.1) -> dict | list | None:
        """Generate and parse a JSON response."""
        raw = self.generate(prompt, system=system,
                           temperature=temperature, json_mode=True)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # Try to extract JSON from the response
            start = raw.find('{')
            end = raw.rfind('}') + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(raw[start:end])
                except json.JSONDecodeError:
                    pass
            start = raw.find('[')
            end = raw.rfind(']') + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(raw[start:end])
                except json.JSONDecodeError:
                    pass
            logger.debug('Failed to parse JSON from Ollama response')
            return None

    # ── Async API ─────────────────────────────────────────────────────────

    async def agenerate(self, prompt: str, system: str = '',
                        temperature: float = 0.3,
                        max_tokens: int = 2048,
                        json_mode: bool = False) -> str:
        """Async generate completion."""
        if not self.is_available():
            return ''

        payload: dict[str, Any] = {
            'model': self.active_model,
            'prompt': prompt,
            'stream': False,
            'options': {
                'temperature': temperature,
                'num_predict': max_tokens,
            },
        }
        if system:
            payload['system'] = system
        if json_mode:
            payload['format'] = 'json'

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f'{self.base_url}/api/generate',
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    data = await resp.json()
                    return data.get('response', '')
        except Exception as e:
            logger.error('Ollama async generate error: %s', e)
            return ''

    async def achat(self, messages: list[dict[str, str]],
                    temperature: float = 0.3,
                    max_tokens: int = 2048,
                    json_mode: bool = False) -> str:
        """Async chat completion."""
        if not self.is_available():
            return ''

        payload: dict[str, Any] = {
            'model': self.active_model,
            'messages': messages,
            'stream': False,
            'options': {
                'temperature': temperature,
                'num_predict': max_tokens,
            },
        }
        if json_mode:
            payload['format'] = 'json'

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f'{self.base_url}/api/chat',
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    data = await resp.json()
                    return data.get('message', {}).get('content', '')
        except Exception as e:
            logger.error('Ollama async chat error: %s', e)
            return ''

    async def agenerate_json(self, prompt: str, system: str = '',
                             temperature: float = 0.1) -> dict | list | None:
        """Async generate and parse JSON response."""
        raw = await self.agenerate(prompt, system=system,
                                   temperature=temperature, json_mode=True)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            start = raw.find('{')
            end = raw.rfind('}') + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(raw[start:end])
                except json.JSONDecodeError:
                    pass
            return None

    # ── Streaming ─────────────────────────────────────────────────────────

    def stream(self, prompt: str, system: str = '',
               temperature: float = 0.3) -> Iterator[str]:
        """Sync streaming generator — yields text chunks."""
        if not self.is_available():
            return

        payload = {
            'model': self.active_model,
            'prompt': prompt,
            'stream': True,
            'options': {'temperature': temperature},
        }
        if system:
            payload['system'] = system

        try:
            resp = requests.post(
                f'{self.base_url}/api/generate',
                json=payload, stream=True, timeout=self.timeout,
            )
            for line in resp.iter_lines():
                if line:
                    data = json.loads(line)
                    chunk = data.get('response', '')
                    if chunk:
                        yield chunk
                    if data.get('done'):
                        break
        except Exception as e:
            logger.error('Ollama stream error: %s', e)

    async def astream(self, prompt: str, system: str = '',
                      temperature: float = 0.3) -> AsyncIterator[str]:
        """Async streaming generator — yields text chunks."""
        if not self.is_available():
            return

        payload = {
            'model': self.active_model,
            'prompt': prompt,
            'stream': True,
            'options': {'temperature': temperature},
        }
        if system:
            payload['system'] = system

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f'{self.base_url}/api/generate',
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    async for line in resp.content:
                        if line:
                            data = json.loads(line)
                            chunk = data.get('response', '')
                            if chunk:
                                yield chunk
                            if data.get('done'):
                                break
        except Exception as e:
            logger.error('Ollama async stream error: %s', e)
