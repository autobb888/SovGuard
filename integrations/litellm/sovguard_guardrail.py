"""
SovGuard custom guardrail for LiteLLM.

Usage (litellm proxy config.yaml):
  guardrails:
    - guardrail_name: "sovguard-input"
      litellm_params:
        guardrail: sovguard_guardrail.SovGuardGuardrail
        mode: "pre_call"
        api_base: "https://api.sovguard.io"
        api_key: os.environ/SOVGUARD_API_KEY

Docs: https://docs.litellm.ai/docs/guardrails/custom_guardrail
"""
import os
from typing import Optional, Literal
import httpx
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.proxy._types import UserAPIKeyAuth
from litellm.exceptions import BadRequestError


class SovGuardGuardrail(CustomGuardrail):
    def __init__(self, api_base: Optional[str] = None, api_key: Optional[str] = None,
                 block_threshold: float = 0.7, **kwargs):
        self.api_base = (api_base or os.getenv("SOVGUARD_API_BASE", "https://api.sovguard.io")).rstrip("/")
        self.api_key = api_key or os.getenv("SOVGUARD_API_KEY", "")
        self.block_threshold = block_threshold
        super().__init__(**kwargs)

    async def async_pre_call_hook(self, user_api_key_dict: UserAPIKeyAuth, cache, data: dict,
                                  call_type: Literal["completion", "text_completion", "embeddings"]):
        messages = data.get("messages", [])
        user_text = "\n".join(m.get("content", "") for m in messages
                              if m.get("role") == "user" and isinstance(m.get("content"), str))
        if not user_text.strip():
            return data
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(f"{self.api_base}/v1/scan",
                                     headers={"X-API-Key": self.api_key},
                                     json={"text": user_text})
            resp.raise_for_status()
            result = resp.json()
        if result.get("degraded") and os.getenv("SOVGUARD_FAIL_CLOSED_ON_DEGRADED") == "1":
            raise BadRequestError(message="SovGuard degraded — refusing (fail-closed).",
                                  model=data.get("model", ""), llm_provider="sovguard")
        if not result.get("safe", True) and result.get("score", 0) >= self.block_threshold:
            raise BadRequestError(
                message=f"Blocked by SovGuard: {result.get('classification','unsafe')} "
                        f"(score={result.get('score')}, flags={[f.get('type') for f in result.get('flags', [])][:5]})",
                model=data.get("model", ""), llm_provider="sovguard")
        return data
