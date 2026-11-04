"""Per-request Nautobot tokens for multi-user deployments.

With ``auth_mode="header"`` the MCP server holds no Nautobot credential of
its own. A gateway in front of it (for example Obot) authenticates the user
against the organisation's identity provider and adds that user's personal
Nautobot API token to every MCP request in a dedicated header
(``X-Nautobot-Token`` by default). Nautobot then applies that user's
permissions and records changes under their name.

The header is client-supplied input, not an identity assertion. The server
only ever uses it as "the token to call Nautobot with"; Nautobot is what
validates it. Anyone who can reach the server directly still needs a valid
Nautobot token, which gives them nothing they could not do against the
Nautobot API itself.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .runtime import bind_request_token

_TOKEN_SCHEME = "token "
# Nautobot keys are 40 hex characters today. Accept a wider, header-safe
# character set so a future key format does not break the server.
_TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]{16,512}")


def token_from_headers(headers: Mapping[str, str] | None, header_name: str) -> str | None:
    """Return the Nautobot token carried in ``headers``, or ``None`` if absent.

    The value may be the bare key or ``Token <key>``. A value that is present
    but malformed, or a header repeated with different values, raises
    ``ValueError`` rather than being ignored.
    """
    if not headers:
        return None

    wanted = header_name.lower()
    values = {value.strip() for name, value in headers.items() if name.lower() == wanted}
    values.discard("")
    if not values:
        return None
    if len(values) > 1:
        raise ValueError(f"The {header_name} header was sent more than once.")

    token = values.pop()
    if token.lower().startswith(_TOKEN_SCHEME):
        token = token[len(_TOKEN_SCHEME) :].strip()
    if not _TOKEN_RE.fullmatch(token):
        # Never echo the value: it may be a real (if mangled) credential.
        raise ValueError(f"The {header_name} header does not contain a valid Nautobot API token.")
    return token


def _headers_of(context: Context | None) -> Mapping[str, str] | None:
    """Return the HTTP headers of the MCP request behind ``context``, if any."""
    if context is None:
        return None
    try:
        return context.headers
    except ValueError:  # no request context, e.g. an in-process call
        return None


class PerRequestTokenServer(MCPServer):
    """An ``MCPServer`` that runs each tool call as the caller's Nautobot user.

    Every tool in this package reaches Nautobot through
    :func:`nautobot_mcp.runtime.get_client`, so binding the token here,
    around the tool call, covers all of them without per-tool changes.
    This server exposes tools only; resources and prompts are not wrapped.
    """

    def __init__(self, *args: Any, token_header: str, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._token_header = token_header

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        context: Context | None = None,
    ) -> Any:
        # Reject before any tool code runs. ToolError (unlike other
        # exceptions) is shown to the caller, so they learn what to fix.
        try:
            token = token_from_headers(_headers_of(context), self._token_header)
        except ValueError as exc:
            raise ToolError(str(exc)) from None
        if token is None:
            raise ToolError(
                "This request has no Nautobot API token. Connect through the MCP "
                f"gateway, which sends your personal token in the {self._token_header} header."
            )

        with bind_request_token(token):
            return await super().call_tool(name, arguments, context)
