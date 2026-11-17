"""
http_get: fetch a web page and return it as plain text.

The shell sandbox has NO network, so this tool is the agent's only way
online, and every call needs your approval. Two security ideas live here:

1. SSRF protection ("server-side request forgery"). A web page could tell
   the agent to fetch http://127.0.0.1:11434/ (your Ollama), your router at
   192.168.1.1, or a cloud metadata service at 169.254.169.254. We resolve
   the host name and refuse any address that isn't on the public internet,
   including after redirects.
   Known gap (a Phase 5 red-team item): "DNS rebinding". The name is looked
   up again when the request is made, and a hostile DNS server could answer
   differently the second time.

2. Untrusted output. Page text is fenced off and labelled as data, because a
   page can contain hidden instructions aimed at the model ("indirect prompt
   injection").
"""

import ipaddress
import re
import socket
import urllib.error
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urlparse

from .. import __version__, config
from .base import Risk, Tool, ToolError, ToolResult, truncate

TEXT_TYPES = ("text/", "application/json", "application/xml", "application/xhtml")


def check_url(url: str) -> str:
    """Raise ToolError unless url is http(s) to a public internet address."""
    parts = urlparse(url)
    if parts.scheme not in ("http", "https"):
        raise ToolError("only http:// and https:// URLs are allowed")
    if not parts.hostname:
        raise ToolError("URL has no host name")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
    except socket.gaierror:
        raise ToolError(f"can't resolve host '{parts.hostname}'") from None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            raise ToolError(f"'{parts.hostname}' resolves to {ip}, a private/local address. Blocked.")
    return url


class _SafeRedirects(urllib.request.HTTPRedirectHandler):
    """Re-check every redirect target, so a public URL can't bounce us to 127.0.0.1."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _TextExtractor(HTMLParser):
    """Keep the visible text of an HTML page; drop scripts, styles and markup."""

    SKIP = {"script", "style", "noscript", "svg", "head", "template"}
    BREAK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article"}

    def __init__(self):
        super().__init__()
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        elif tag in self.BREAK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(re.sub(r"\s+", " ", data))   # newlines in HTML source are just spaces


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    lines = (" ".join(line.split()) for line in "".join(parser.parts).splitlines())
    return "\n".join(line for line in lines if line)


class HttpGet(Tool):
    name = "http_get"
    description = "Download a public web page (http/https) and return its text. Needs user approval."
    parameters = {
        "type": "object",
        "properties": {"url": {"type": "string", "description": "Full URL, e.g. https://example.com"}},
        "required": ["url"],
    }
    risk = Risk.NETWORK

    def describe(self, args):
        return f"GET {args.get('url')}"

    def run(self, url):
        check_url(url)
        opener = urllib.request.build_opener(_SafeRedirects)
        req = urllib.request.Request(url, headers={"User-Agent": f"AgenticOS/{__version__} (personal agent)"})
        try:
            with opener.open(req, timeout=config.HTTP_TIMEOUT) as resp:
                ctype = resp.headers.get("Content-Type", "")
                if not ctype.startswith(TEXT_TYPES):
                    raise ToolError(f"not a text page (Content-Type: {ctype or 'unknown'})")
                body = resp.read(config.HTTP_MAX_BYTES + 1)
                status, final_url = resp.status, resp.geturl()
        except urllib.error.HTTPError as e:
            raise ToolError(f"HTTP {e.code} {e.reason}") from None
        except urllib.error.URLError as e:
            raise ToolError(f"request failed: {e.reason}") from None
        except TimeoutError:
            raise ToolError(f"timed out after {config.HTTP_TIMEOUT}s") from None
        too_big = len(body) > config.HTTP_MAX_BYTES
        text = body[: config.HTTP_MAX_BYTES].decode("utf-8", errors="replace")
        if "html" in ctype:
            text = html_to_text(text)
        text, cut = truncate(text)
        return ToolResult(True, text, truncated=cut or too_big, untrusted=True,
                          meta={"status": status, "url": final_url})
