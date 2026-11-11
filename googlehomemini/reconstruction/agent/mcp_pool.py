"""MCP client pool — manages stdio MCP server connections and routes tool calls."""
import asyncio
import json
import logging
from typing import Any

from config import MCP_SERVERS

log = logging.getLogger(__name__)

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    HAS_MCP = True
except ImportError:
    HAS_MCP = False
    log.warning("mcp package not installed; MCP tools unavailable")


class MCPPool:
    """Holds N open MCP sessions. Call tool() to invoke a tool by name."""

    def __init__(self):
        self._sessions: dict[str, Any] = {}   # server_name → ClientSession
        self._schemas: dict[str, dict] = {}   # tool_name → tool schema

    async def start(self):
        if not HAS_MCP:
            return
        for srv in MCP_SERVERS:
            name = srv["name"]
            params = StdioServerParameters(
                command=srv["command"],
                args=srv.get("args", []),
                env=srv.get("env"),
            )
            try:
                _stdio, session = await stdio_client(params).__aenter__()
                await session.initialize()
                tools = await session.list_tools()
                self._sessions[name] = session
                for tool in tools.tools:
                    self._schemas[tool.name] = {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.inputSchema,
                        "_server": name,
                    }
                log.info("MCP server %r: %d tools", name, len(tools.tools))
            except Exception as e:
                log.error("MCP server %r failed to start: %s", name, e)

    def tool_schemas(self) -> list[dict]:
        """Return tool definitions in Ollama/OpenAI function-call format."""
        schemas = []
        for t in self._schemas.values():
            schemas.append({
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["parameters"],
                },
            })
        return schemas

    async def call(self, tool_name: str, arguments: dict) -> str:
        schema = self._schemas.get(tool_name)
        if schema is None:
            return f"[unknown tool: {tool_name}]"
        server_name = schema["_server"]
        session = self._sessions.get(server_name)
        if session is None:
            return f"[server {server_name!r} not connected]"
        try:
            result = await session.call_tool(tool_name, arguments)
            parts = [c.text for c in result.content if hasattr(c, "text")]
            return "\n".join(parts)
        except Exception as e:
            log.error("MCP tool %r failed: %s", tool_name, e)
            return f"[tool error: {e}]"
