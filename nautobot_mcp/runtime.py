"""Process-wide runtime state for the MCP server.

The MCP tool functions need access to a shared :class:`NautobotClient`
instance. We hold it here so tool modules can grab it lazily without
creating import cycles with the server module.

In per-request token mode (``auth_mode="header"``) the shared client holds
no credential. The caller's token is bound to the current tool call with a
:class:`~contextvars.ContextVar`, and :func:`get_client` hands each call a
client that authenticates as that caller.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .client import NautobotClient
    from .config import NautobotMcpSettings


_client: NautobotClient | None = None
_settings: NautobotMcpSettings | None = None
_enabled_plugins: tuple[str, ...] = ()
_request_token: ContextVar[str | None] = ContextVar("nautobot_request_token", default=None)


def set_client(client: NautobotClient) -> None:
    """Register the active NautobotClient (called from server lifespan)."""
    global _client
    _client = client


def get_client() -> NautobotClient:
    """Return the client to use for the current tool call.

    In static mode this is the shared client. In per-request token mode it
    is a client authenticated as the caller; there is deliberately no
    fallback, so a request without a token fails instead of running under
    someone else's identity.
    """
    if _client is None:
        raise RuntimeError(
            "NautobotClient is not initialized. The MCP server must be "
            "started via nautobot_mcp.server.main()."
        )
    if _settings is None or not _settings.per_request_token:
        return _client

    token = _request_token.get()
    if token is None:
        raise PermissionError(
            "This request has no Nautobot API token. The MCP gateway must send "
            f"the caller's personal token in the {_settings.token_header} header."
        )
    return _client.for_token(token)


@contextmanager
def bind_request_token(token: str | None) -> Iterator[None]:
    """Make ``token`` the caller's Nautobot token for the enclosed tool call."""
    reset_token = _request_token.set(token)
    try:
        yield
    finally:
        _request_token.reset(reset_token)


def set_settings(settings: NautobotMcpSettings) -> None:
    """Register the active settings."""
    global _settings
    _settings = settings


def get_settings() -> NautobotMcpSettings:
    """Return the active settings or raise if not initialized."""
    if _settings is None:
        raise RuntimeError("Settings not initialized.")
    return _settings


def set_enabled_plugins(keys: tuple[str, ...]) -> None:
    """Record which plugin integrations were enabled at registration."""
    global _enabled_plugins
    _enabled_plugins = keys


def get_enabled_plugins() -> tuple[str, ...]:
    """Return the plugin integrations enabled for this server."""
    return _enabled_plugins


def reset() -> None:
    """Clear runtime state (useful for tests)."""
    global _client, _settings, _enabled_plugins
    _client = None
    _settings = None
    _enabled_plugins = ()
