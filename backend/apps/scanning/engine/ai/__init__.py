"""
AI Module — Local LLM integration (Ollama) and intelligent analysis
components for human-like penetration testing reasoning.
"""
from .ollama_client import OllamaClient
from .reasoning import LLMReasoningEngine
from .context_analyzer import ContextAnalyzer

__all__ = [
    'OllamaClient',
    'LLMReasoningEngine',
    'ContextAnalyzer',
]
