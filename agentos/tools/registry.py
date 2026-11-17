"""
The tool registry: finds every tool and hands their schemas to the model.

"Add a tool by dropping in one file" works like this: discover() imports
every module in agentos/tools/, collects each concrete Tool subclass, and
creates one instance of it. Nothing else needs editing.

It also loads tools from MCP servers listed in mcp_servers.json.
"""

import importlib
import inspect
import pkgutil

from .base import Tool

SKIP_MODULES = {"base", "registry", "mcp_client"}


class ToolRegistry:
    def __init__(self, tools=()):
        self._tools = {}
        self.warnings = []
        for t in tools:
            self.add(t)

    def add(self, tool: Tool):
        if not tool.name:
            raise ValueError(f"{type(tool).__name__} has no name")
        if tool.name in self._tools:
            raise ValueError(f"two tools are called '{tool.name}'")
        self._tools[tool.name] = tool

    def get(self, name):
        return self._tools.get(name)

    def names(self):
        return list(self._tools)

    def schemas(self):
        return [t.schema() for t in self._tools.values()]

    def __iter__(self):
        return iter(self._tools.values())

    def __len__(self):
        return len(self._tools)

    @classmethod
    def discover(cls, package="agentos.tools", include_mcp=True):
        reg = cls()
        pkg = importlib.import_module(package)
        for info in sorted(pkgutil.iter_modules(pkg.__path__), key=lambda i: i.name):
            if info.name.startswith("_") or info.name in SKIP_MODULES:
                continue
            module = importlib.import_module(f"{package}.{info.name}")
            for _, obj in sorted(vars(module).items()):
                if (inspect.isclass(obj) and issubclass(obj, Tool) and obj is not Tool
                        and not inspect.isabstract(obj) and obj.__module__ == module.__name__):
                    reg.add(obj())
        if include_mcp:
            from .mcp_client import load_mcp_tools
            tools, warnings = load_mcp_tools()
            for t in tools:
                reg.add(t)
            reg.warnings.extend(warnings)
        return reg
