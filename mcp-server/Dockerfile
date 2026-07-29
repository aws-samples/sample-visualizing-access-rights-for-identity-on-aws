# ARM64 image for hosting the ARIA-gv MCP server on Amazon Bedrock AgentCore
# Runtime. AgentCore requires an ARM64 container that serves the MCP protocol
# over streamable-HTTP on 0.0.0.0:8000 at /mcp.
FROM --platform=linux/arm64 python:3.12-slim

# Do not buffer stdout/stderr so logs reach CloudWatch promptly.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install the package. Copy metadata first for better layer caching.
COPY pyproject.toml README.md ./
COPY aria_mcp_server ./aria_mcp_server
RUN pip install --no-cache-dir .

# Run as a non-root user.
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000

# Liveness check: confirm the streamable-HTTP server is listening on 8000.
# Uses a TCP connect via the in-image Python (no curl in slim images), and works
# as the non-root user. Note: AgentCore Runtime manages health at the MCP
# protocol layer and does not consume this; it applies when the image runs under
# Docker/ECS and satisfies container security scanners.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('127.0.0.1', 8000)); s.close()" || exit 1

# Streamable-HTTP entrypoint (0.0.0.0:8000, path /mcp, stateless).
CMD ["aria-gv-mcp-http"]
