"""Base multi-provider LLM agent with resilient offline mock support."""

import json
import logging
import os
from typing import Any, Optional
from scannex.config import ScannexConfig

logger = logging.getLogger(__name__)


class BaseAgent:
    """Multi-provider LLM client supporting LiteLLM, Ollama, and zero-key Mock mode."""

    def __init__(self, config: Optional[ScannexConfig] = None):
        self.config = config or ScannexConfig.from_env()

    async def call_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: Optional[dict[str, Any]] = None,
    ) -> str:
        """Execute an LLM prompt via LiteLLM or fall back to mock execution."""
        if self.config.mock_mode:
            return self._mock_response(system_prompt, user_prompt)

        try:
            import litellm

            timeout = getattr(self.config, "llm_timeout_sec", 180)
            kwargs: dict[str, Any] = {
                "model": self.config.model_name,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.1,
                "timeout": timeout,
                "max_tokens": 1500,
            }

            # Configure Ollama IPv4 host to avoid Windows IPv6 resolution hang
            if self.config.model_name.startswith("ollama/"):
                kwargs["api_base"] = os.getenv("OLLAMA_API_BASE", "http://127.0.0.1:11434")

            if response_format:
                kwargs["response_format"] = response_format

            response = await litellm.acompletion(**kwargs)
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.warning(f"Live LLM call failed ({e}); falling back to offline mock mode.")
            return self._mock_response(system_prompt, user_prompt)

    def _mock_response(self, system_prompt: str, user_prompt: str) -> str:
        """Override in subclasses to provide realistic deterministic mock responses."""
        return "{}"
