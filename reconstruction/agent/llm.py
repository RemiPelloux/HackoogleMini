"""LLM inference via Ollama with optional MCP tool calls."""
import asyncio
import json
import logging
from typing import TYPE_CHECKING

import ollama

from config import LLM_SYSTEM_PROMPT, LLM_TIMEOUT_SEC, OLLAMA_HOST, OLLAMA_MODEL

if TYPE_CHECKING:
    from mcp_pool import MCPPool

log = logging.getLogger(__name__)

_client: ollama.AsyncClient | None = None


def _get_client() -> ollama.AsyncClient:
    global _client
    if _client is None:
        _client = ollama.AsyncClient(host=OLLAMA_HOST)
    return _client


async def respond(text: str, pool: "MCPPool") -> str:
    """Send `text` to the LLM, execute any tool calls via `pool`, return reply."""
    client = _get_client()
    tools = pool.tool_schemas() if pool else []

    messages = [
        {"role": "system", "content": LLM_SYSTEM_PROMPT},
        {"role": "user",   "content": text},
    ]

    for _ in range(5):  # max tool-call rounds
        kwargs: dict = {
            "model": OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
        }
        if tools:
            kwargs["tools"] = tools

        try:
            response = await asyncio.wait_for(
                client.chat(**kwargs),
                timeout=LLM_TIMEOUT_SEC,
            )
        except asyncio.TimeoutError:
            log.error("LLM timeout after %ds", LLM_TIMEOUT_SEC)
            return "Sorry, the LLM timed out."

        msg = response.message
        messages.append({"role": "assistant", "content": msg.content or "",
                          "tool_calls": msg.tool_calls})

        if not msg.tool_calls:
            return (msg.content or "").strip()

        # Execute tool calls
        for tc in msg.tool_calls:
            fn = tc.function
            log.info("Tool call: %s(%s)", fn.name, fn.arguments)
            result = await pool.call(fn.name, fn.arguments or {})
            log.debug("Tool result: %r", result[:200])
            messages.append({
                "role": "tool",
                "content": result,
            })

    return "Sorry, too many tool rounds."
