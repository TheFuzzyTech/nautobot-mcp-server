"""Configuration loading for the Nautobot MCP server.

Resolution order (highest priority first):

1. Explicit kwargs passed to :func:`load_settings`.
2. Environment variables (``NAUTOBOT_URL``, ``NAUTOBOT_TOKEN``, and the
   ``NAUTOBOT_MCP_*`` settings below). Unprefixed legacy aliases
   (``NAUTOBOT_ALLOW_WRITES``, ``NAUTOBOT_TENANT_SCOPE``, …) are still
   accepted but the ``NAUTOBOT_MCP_*`` form wins when both are set.
3. ``settings.PLUGINS_CONFIG["nautobot_mcp"]`` when running inside
   Nautobot/Django.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

# Canonical env names → optional legacy aliases (deprecated).
# Connection credentials stay as NAUTOBOT_URL / NAUTOBOT_TOKEN; MCP-specific
# behaviour uses the NAUTOBOT_MCP_ prefix to avoid colliding with Nautobot core.
_ENV_ALIASES: dict[str, tuple[str, ...]] = {
    "NAUTOBOT_MCP_VERIFY_SSL": ("NAUTOBOT_VERIFY_SSL",),
    "NAUTOBOT_MCP_CA_BUNDLE": ("NAUTOBOT_CA_BUNDLE",),
    "NAUTOBOT_MCP_TIMEOUT": ("NAUTOBOT_TIMEOUT",),
    "NAUTOBOT_MCP_MAX_PAGINATION_RECORDS": ("NAUTOBOT_MAX_PAGINATION_RECORDS",),
    "NAUTOBOT_MCP_ALLOW_WRITES": ("NAUTOBOT_ALLOW_WRITES",),
    "NAUTOBOT_MCP_TENANT_SCOPE": ("NAUTOBOT_TENANT_SCOPE",),
    "NAUTOBOT_MCP_TENANT_GROUP_SCOPE": ("NAUTOBOT_TENANT_GROUP_SCOPE",),
    "NAUTOBOT_MCP_LOG_LEVEL": ("MCP_LOG_LEVEL",),
}

# How the server authenticates to Nautobot:
#   "static" - one shared token from NAUTOBOT_TOKEN / PLUGINS_CONFIG (default).
#   "header" - each MCP request carries the caller's own Nautobot token in an
#              HTTP header (set by a gateway such as Obot), so Nautobot sees
#              and audits the real user. HTTP transports only.
AUTH_MODE_STATIC = "static"
AUTH_MODE_HEADER = "header"
_AUTH_MODES = frozenset({AUTH_MODE_STATIC, AUTH_MODE_HEADER})
DEFAULT_TOKEN_HEADER = "X-Nautobot-Token"
_HEADER_NAME_RE = re.compile(r"[A-Za-z0-9-]+")


def _getenv(name: str) -> str | None:
    """Read ``name``, falling back to any registered legacy aliases."""
    value = os.getenv(name)
    if value not in (None, ""):
        return value
    for alias in _ENV_ALIASES.get(name, ()):
        alias_val = os.getenv(alias)
        if alias_val not in (None, ""):
            return alias_val
    return value  # None or ""


def _coerce_str_tuple(value: Any) -> tuple[str, ...]:
    """Coerce a value into a tuple of non-empty strings.

    Accepts a list/tuple, or a comma-separated string (handy for env vars
    like ``NAUTOBOT_MCP_TENANT_SCOPE=acme,globex``).
    """
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        items: list[Any] = list(value)
    else:
        items = str(value).split(",")
    return tuple(s.strip() for s in (str(i) for i in items) if s.strip())


def _coerce_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text == "":
        return default
    return text not in {"0", "false", "no", "off"}


def _from_django_settings() -> dict[str, Any]:
    """Pull plugin config from Nautobot's PLUGINS_CONFIG, if available."""
    try:
        from django.conf import settings  # type: ignore[import-not-found]
    except ImportError:
        return {}
    try:
        plugins_config = getattr(settings, "PLUGINS_CONFIG", {}) or {}
        cfg = plugins_config.get("nautobot_mcp", {}) or {}
        return dict(cfg)
    except Exception:
        return {}


@dataclass(frozen=True)
class NautobotMcpSettings:
    """Resolved runtime settings for the MCP server."""

    url: str
    token: str
    verify_ssl: bool | str = True
    request_timeout: float = 30.0
    max_pagination_records: int = 5000
    allow_writes: bool = False
    log_level: str = "INFO"
    tenant_scope: tuple[str, ...] = ()
    tenant_group_scope: tuple[str, ...] = ()
    plugins: tuple[str, ...] = ("auto",)
    auth_mode: str = AUTH_MODE_STATIC
    token_header: str = DEFAULT_TOKEN_HEADER

    @property
    def tenant_scoped(self) -> bool:
        """True when any tenant or tenant-group restriction is configured."""
        return bool(self.tenant_scope or self.tenant_group_scope)

    @property
    def per_request_token(self) -> bool:
        """True when each request must supply its own Nautobot token."""
        return self.auth_mode == AUTH_MODE_HEADER

    def redacted(self) -> dict[str, Any]:
        """Return a dict suitable for logging (token masked)."""
        if self.per_request_token:
            token_preview = f"<per-request via {self.token_header}>"
        elif len(self.token) >= 8:
            token_preview = f"{self.token[:4]}…{self.token[-4:]}"
        else:
            token_preview = "<set>"
        return {
            "url": self.url,
            "auth_mode": self.auth_mode,
            "token": token_preview,
            "verify_ssl": self.verify_ssl,
            "request_timeout": self.request_timeout,
            "max_pagination_records": self.max_pagination_records,
            "allow_writes": self.allow_writes,
            "log_level": self.log_level,
            "tenant_scope": list(self.tenant_scope),
            "tenant_group_scope": list(self.tenant_group_scope),
            "plugins": list(self.plugins),
        }


def load_settings(**overrides: Any) -> NautobotMcpSettings:
    """Resolve settings from kwargs > env > Django PLUGINS_CONFIG."""
    django_cfg = _from_django_settings()

    def _pick(key: str, env: str, *, default: Any = None) -> Any:
        if overrides.get(key) not in (None, ""):
            return overrides[key]
        env_val = _getenv(env)
        if env_val not in (None, ""):
            return env_val
        django_val = django_cfg.get(_django_key(key))
        if django_val not in (None, ""):
            return django_val
        return default

    url = str(_pick("url", "NAUTOBOT_URL", default="") or "").rstrip("/")
    token = str(_pick("token", "NAUTOBOT_TOKEN", default="") or "")

    # SSL verification: bool, or path to CA bundle, or False to disable.
    ca_bundle = (
        overrides.get("ca_bundle")
        or _getenv("NAUTOBOT_MCP_CA_BUNDLE")
        or django_cfg.get("ca_bundle")
        or ""
    )
    if "verify_ssl" in overrides and overrides["verify_ssl"] is not None:
        verify_ssl: bool | str = overrides["verify_ssl"]
    elif ca_bundle:
        verify_ssl = str(ca_bundle)
    elif _getenv("NAUTOBOT_MCP_VERIFY_SSL") is not None:
        verify_ssl = _coerce_bool(_getenv("NAUTOBOT_MCP_VERIFY_SSL"), True)
    else:
        verify_ssl = bool(django_cfg.get("verify_ssl", True))

    request_timeout = float(
        _pick("request_timeout", "NAUTOBOT_MCP_TIMEOUT", default=30.0) or 30.0
    )
    max_pagination_records = int(
        _pick(
            "max_pagination_records",
            "NAUTOBOT_MCP_MAX_PAGINATION_RECORDS",
            default=5000,
        )
        or 5000
    )
    allow_writes = _coerce_bool(
        _pick("allow_writes", "NAUTOBOT_MCP_ALLOW_WRITES", default=False), False
    )
    log_level = str(
        _pick("log_level", "NAUTOBOT_MCP_LOG_LEVEL", default="INFO") or "INFO"
    ).upper()
    tenant_scope = _coerce_str_tuple(
        _pick("tenant_scope", "NAUTOBOT_MCP_TENANT_SCOPE", default=())
    )
    tenant_group_scope = _coerce_str_tuple(
        _pick("tenant_group_scope", "NAUTOBOT_MCP_TENANT_GROUP_SCOPE", default=())
    )
    plugins = _coerce_str_tuple(
        _pick("plugins", "NAUTOBOT_MCP_PLUGINS", default="auto")
    ) or ("auto",)
    auth_mode = str(
        _pick("auth_mode", "NAUTOBOT_MCP_AUTH_MODE", default=AUTH_MODE_STATIC)
    ).strip().lower()
    token_header = str(
        _pick("token_header", "NAUTOBOT_MCP_TOKEN_HEADER", default=DEFAULT_TOKEN_HEADER)
    ).strip()

    if not url:
        raise ValueError(
            "Nautobot URL is not configured. Set the NAUTOBOT_URL env var "
            "or PLUGINS_CONFIG['nautobot_mcp']['nautobot_url']."
        )
    _validate_auth(auth_mode, token, token_header)

    return NautobotMcpSettings(
        url=url,
        token=token,
        verify_ssl=verify_ssl,
        request_timeout=request_timeout,
        max_pagination_records=max_pagination_records,
        allow_writes=allow_writes,
        log_level=log_level,
        tenant_scope=tenant_scope,
        tenant_group_scope=tenant_group_scope,
        plugins=tuple(p.lower().replace("-", "_") for p in plugins),
        auth_mode=auth_mode,
        token_header=token_header,
    )


def _validate_auth(auth_mode: str, token: str, token_header: str) -> None:
    """Reject auth configurations that are ambiguous or unsafe."""
    if auth_mode not in _AUTH_MODES:
        raise ValueError(
            f"NAUTOBOT_MCP_AUTH_MODE must be one of {sorted(_AUTH_MODES)}, "
            f"got {auth_mode!r}."
        )

    if auth_mode == AUTH_MODE_STATIC:
        if not token:
            raise ValueError(
                "Nautobot API token is not configured. Set the NAUTOBOT_TOKEN env "
                "var or PLUGINS_CONFIG['nautobot_mcp']['nautobot_token']."
            )
        return

    # Header mode. A shared token alongside it would be a silent fallback that
    # attributes other people's changes to its owner, so refuse to start.
    if token:
        raise ValueError(
            "NAUTOBOT_TOKEN must not be set when NAUTOBOT_MCP_AUTH_MODE=header; "
            "every request supplies its own token."
        )
    if not _HEADER_NAME_RE.fullmatch(token_header):
        raise ValueError(
            f"NAUTOBOT_MCP_TOKEN_HEADER {token_header!r} is not a valid HTTP header name."
        )
    # The Authorization header normally carries the gateway's own credential;
    # forwarding it to Nautobot would be token passthrough.
    if token_header.lower() == "authorization":
        raise ValueError(
            "NAUTOBOT_MCP_TOKEN_HEADER must not be 'Authorization'; use a "
            f"dedicated header such as {DEFAULT_TOKEN_HEADER!r}."
        )


def _django_key(key: str) -> str:
    """Map an internal setting name to the Django PLUGINS_CONFIG key."""
    return {
        "url": "nautobot_url",
        "token": "nautobot_token",
    }.get(key, key)
