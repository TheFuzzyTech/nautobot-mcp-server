# nautobot-mcp for a multi-user MCP gateway (e.g. Obot).
#
# The image holds no Nautobot credential. It runs in per-request token mode:
# the gateway adds each signed-in user's own Nautobot API token to every MCP
# request, so Nautobot enforces that user's permissions and logs changes
# under their name.
#
# Build from the repository root:
#   docker build -f deploy/Dockerfile -t ghcr.io/YOUR-ORG/nautobot-mcp:0.2.5-peruser1 .
#
# Tip: pin the base image by digest (and let Renovate/Dependabot bump it).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY nautobot_mcp ./nautobot_mcp
RUN pip install . && rm -rf /src

RUN useradd --system --uid 10001 --no-create-home mcp
USER 10001
WORKDIR /

ENV NAUTOBOT_MCP_AUTH_MODE=header \
    NAUTOBOT_MCP_HOST=0.0.0.0 \
    NAUTOBOT_MCP_PORT=8000

EXPOSE 8000
# Streamable HTTP is served at /mcp. CMD (not ENTRYPOINT) so a gateway's
# container args can replace the whole command line.
CMD ["nautobot-mcp", "--transport", "streamable-http"]
