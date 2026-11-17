"""
A tiny MCP server, to show how external tools plug into Agentic OS.

Enable it in mcp_servers.json ("enabled": true), then run
    python main.py --list-tools
and you'll see mcp_demo_word_count and mcp_demo_roll_dice next to the built-in tools.

Works with both versions of the MCP Python SDK (v1 calls the class FastMCP,
v2 renamed it MCPServer).
"""

import random

try:
    from mcp.server.mcpserver import MCPServer as Server   # mcp >= 2
except ImportError:
    from mcp.server.fastmcp import FastMCP as Server       # mcp 1.x

server = Server("agentos-demo")


@server.tool()
def word_count(text: str) -> str:
    """Count the words, lines and characters in a piece of text."""
    return f"words: {len(text.split())}, lines: {len(text.splitlines())}, characters: {len(text)}"


@server.tool()
def roll_dice(sides: int = 6, count: int = 1) -> str:
    """Roll `count` dice with `sides` sides each and return the results."""
    if not (1 <= count <= 20 and 2 <= sides <= 1000):
        return "error: count must be 1-20 and sides 2-1000"
    rolls = [random.randint(1, sides) for _ in range(count)]
    return f"rolls: {rolls}, total: {sum(rolls)}"


if __name__ == "__main__":
    server.run()     # speaks MCP over stdin/stdout
