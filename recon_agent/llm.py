"""DeepSeek chat model via the OpenAI-compatible API.

DeepSeek exposes an OpenAI-compatible endpoint, so we reuse ChatOpenAI and only
point base_url at DeepSeek. The model name and key come from the environment
(see .env.example).
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from langchain_openai import ChatOpenAI


def build_llm(temperature: float = 0.0) -> ChatOpenAI:
    # Imported lazily so offline/fake-model runs (which pass their own llm and
    # never call this) don't require the langchain-openai stack to be installed.
    from langchain_openai import ChatOpenAI

    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        raise RuntimeError(
            "DEEPSEEK_API_KEY is not set. Copy .env.example to .env and fill it in, "
            "or export the variable in your shell."
        )
    return ChatOpenAI(
        model=os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"),
        api_key=api_key,
        base_url=os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
        temperature=temperature,
        timeout=120,
    )
