"""Tests for per-request (per-user) Nautobot tokens: ``auth_mode="header"``."""

from __future__ import annotations

import asyncio
import contextlib

import anyio
import httpx
import pytest
import respx

from nautobot_mcp import runtime
from nautobot_mcp.client import NautobotClient
from nautobot_mcp.config import NautobotMcpSettings, load_settings
from nautobot_mcp.request_auth import token_from_headers

NAUTOBOT = "https://nautobot.example.com"
ALICE = "a" * 40
BOB = "b" * 40


def _header_settings(**overrides) -> NautobotMcpSettings:
    base = dict(url=NAUTOBOT, token="", auth_mode="header", log_level="WARNING")
    base.update(overrides)
    return NautobotMcpSettings(**base)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch):
    """Keep the developer's own environment and global state out of each test."""
    for name in (
        "NAUTOBOT_URL",
        "NAUTOBOT_TOKEN",
        "NAUTOBOT_MCP_AUTH_MODE",
        "NAUTOBOT_MCP_TOKEN_HEADER",
    ):
        monkeypatch.delenv(name, raising=False)
    runtime.reset()
    yield
    runtime.reset()


# ---- configuration --------------------------------------------------------


def test_header_mode_needs_no_shared_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NAUTOBOT_URL", NAUTOBOT)
    monkeypatch.setenv("NAUTOBOT_MCP_AUTH_MODE", "header")

    s = load_settings()

    assert s.per_request_token
    assert s.token_header == "X-Nautobot-Token"
    assert s.redacted()["token"] == "<per-request via X-Nautobot-Token>"


def test_header_mode_refuses_a_shared_token_fallback() -> None:
    with pytest.raises(ValueError, match="must not be set"):
        load_settings(url=NAUTOBOT, token=ALICE, auth_mode="header")


def test_unknown_auth_mode_is_rejected() -> None:
    with pytest.raises(ValueError, match="AUTH_MODE"):
        load_settings(url=NAUTOBOT, token=ALICE, auth_mode="oauth")


@pytest.mark.parametrize("header", ["Authorization", "authorization", "X Bad", "X-Tok\nen"])
def test_unsafe_token_header_names_are_rejected(header: str) -> None:
    with pytest.raises(ValueError, match="TOKEN_HEADER"):
        load_settings(url=NAUTOBOT, auth_mode="header", token_header=header)


def test_static_mode_is_still_the_default() -> None:
    s = load_settings(url=NAUTOBOT, token=ALICE)
    assert not s.per_request_token


# ---- header parsing --------------------------------------------------------


@pytest.mark.parametrize("headers", [None, {}, {"x-other": "1"}, {"x-nautobot-token": "  "}])
def test_missing_header_means_no_token(headers) -> None:
    assert token_from_headers(headers, "X-Nautobot-Token") is None


@pytest.mark.parametrize("value", [ALICE, f"Token {ALICE}", f"  token {ALICE} "])
def test_token_is_read_case_insensitively(value: str) -> None:
    assert token_from_headers({"x-nautobot-token": value}, "X-Nautobot-Token") == ALICE


def test_malformed_token_is_rejected_without_echoing_it() -> None:
    with pytest.raises(ValueError) as excinfo:
        token_from_headers({"X-Nautobot-Token": "short;secret"}, "X-Nautobot-Token")
    assert "short;secret" not in str(excinfo.value)


def test_conflicting_duplicate_headers_are_rejected() -> None:
    class _MultiHeaders(dict):
        def items(self):
            return [("x-nautobot-token", ALICE), ("X-Nautobot-Token", BOB)]

    with pytest.raises(ValueError, match="more than once"):
        token_from_headers(_MultiHeaders(x=1), "X-Nautobot-Token")


# ---- client ---------------------------------------------------------------


@respx.mock
async def test_token_clients_share_a_pool_but_not_credentials() -> None:
    route = respx.get(f"{NAUTOBOT}/api/status/").mock(return_value=httpx.Response(200, json={}))
    shared = NautobotClient(_header_settings())
    alice, bob = shared.for_token(ALICE), shared.for_token(BOB)

    await alice.status()
    await bob.status()
    await alice.aclose()  # must not close the shared pool
    await bob.status()
    await shared.aclose()

    sent = [call.request.headers["Authorization"] for call in route.calls]
    assert sent == [f"Token {ALICE}", f"Token {BOB}", f"Token {BOB}"]
    assert alice._client is shared._client is bob._client


@respx.mock
async def test_client_without_a_token_never_calls_nautobot() -> None:
    route = respx.get(f"{NAUTOBOT}/api/status/").mock(return_value=httpx.Response(200, json={}))
    shared = NautobotClient(_header_settings())

    with pytest.raises(PermissionError):
        await shared.status()
    await shared.aclose()

    assert not route.called


@respx.mock
async def test_job_runs_are_authenticated_and_not_retried() -> None:
    run = respx.post(f"{NAUTOBOT}/api/extras/jobs/j1/run/").mock(return_value=httpx.Response(503))
    shared = NautobotClient(_header_settings())

    with pytest.raises(httpx.HTTPStatusError):
        await shared.for_token(ALICE).run_job("j1", {"data": {}})
    await shared.aclose()

    assert run.call_count == 1  # a retry could start the job twice
    assert run.calls.last.request.headers["Authorization"] == f"Token {ALICE}"


@respx.mock
async def test_shared_pool_never_replays_a_session_cookie() -> None:
    route = respx.get(f"{NAUTOBOT}/api/status/").mock(
        return_value=httpx.Response(200, json={}, headers={"Set-Cookie": "sessionid=alice"})
    )
    shared = NautobotClient(_header_settings())

    await shared.for_token(ALICE).status()
    await shared.for_token(BOB).status()
    await shared.aclose()

    assert "cookie" not in route.calls.last.request.headers


@respx.mock(assert_all_called=False)
async def test_pagination_links_stay_on_the_configured_nautobot(
    respx_mock: respx.MockRouter,
) -> None:
    # A TLS-terminating proxy makes Nautobot emit http:// links; a hostile or
    # misconfigured one could point elsewhere. Neither may receive the token.
    # Routes go on ``respx_mock``: a configured respx.mock(...) has its own router.
    off_origin = respx_mock.route(host="evil.example.com")
    plain_http = respx_mock.route(scheme="http")
    pages = respx_mock.get(f"{NAUTOBOT}/api/dcim/devices/").mock(
        side_effect=[
            httpx.Response(
                200,
                json={"results": [1], "next": "http://evil.example.com/api/dcim/devices/?offset=1"},
            ),
            httpx.Response(200, json={"results": [2], "next": None}),
        ]
    )
    shared = NautobotClient(_header_settings())

    results = await shared.for_token(ALICE).rest_list("/api/dcim/devices/", paginate=True)
    await shared.aclose()

    assert results == [1, 2]
    assert not off_origin.called and not plain_http.called
    second = pages.calls.last.request
    assert str(second.url) == f"{NAUTOBOT}/api/dcim/devices/?offset=1"
    assert second.headers["Authorization"] == f"Token {ALICE}"


# ---- runtime --------------------------------------------------------------


async def test_get_client_fails_closed_without_a_bound_token() -> None:
    settings = _header_settings()
    shared = NautobotClient(settings)
    runtime.set_settings(settings)
    runtime.set_client(shared)

    with pytest.raises(PermissionError, match="X-Nautobot-Token"):
        runtime.get_client()

    with runtime.bind_request_token(ALICE):
        assert runtime.get_client()._auth_headers == {"Authorization": f"Token {ALICE}"}

    with pytest.raises(PermissionError):
        runtime.get_client()  # binding does not leak past the call
    await shared.aclose()


# ---- end to end over streamable HTTP --------------------------------------


@contextlib.asynccontextmanager
async def _running_server(settings: NautobotMcpSettings):
    import uvicorn

    from nautobot_mcp.server import build_server

    app = build_server(settings).streamable_http_app(host="127.0.0.1")
    # Port 0 lets the OS pick a free port, with no race to claim it.
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    task = asyncio.create_task(server.serve())
    with anyio.fail_after(10):  # asyncio.timeout needs Python 3.11+
        while not server.started:
            if task.done():  # startup failed; surface the real error
                task.result()
            await asyncio.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        await task


async def _call_status(url: str, headers: dict[str, str]):
    # The MCP SDK client uses httpx2, so respx (which patches httpx) only
    # intercepts the server's calls to Nautobot, not this client's calls.
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    async with (
        httpx2.AsyncClient(headers=headers) as http,
        Client(streamable_http_client(url, http_client=http)) as client,
    ):
        return await client.call_tool("nautobot_status", {})


@respx.mock
async def test_each_mcp_caller_reaches_nautobot_as_themselves() -> None:
    nautobot = respx.get(f"{NAUTOBOT}/api/status/").mock(
        return_value=httpx.Response(200, json={"nautobot-version": "2.4.0"})
    )

    async with _running_server(_header_settings()) as url:
        alice = await _call_status(url, {"X-Nautobot-Token": ALICE})
        bob = await _call_status(url, {"X-Nautobot-Token": f"Token {BOB}"})
        nobody = await _call_status(url, {})
        garbled = await _call_status(url, {"X-Nautobot-Token": "not a token"})

    assert not alice.is_error and not bob.is_error
    assert nobody.is_error and "X-Nautobot-Token" in nobody.content[0].text
    assert garbled.is_error
    sent = [call.request.headers["Authorization"] for call in nautobot.calls]
    assert sent == [f"Token {ALICE}", f"Token {BOB}"]
