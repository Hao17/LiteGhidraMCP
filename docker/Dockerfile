FROM blacktop/ghidra:11.0 AS base

# Install Python dependencies (Ghidrathon is already built-in)
COPY requirements.txt /tmp/
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Set working directory
WORKDIR /app

# Copy source code (preserving directory structure)
COPY ghidra_mcp_server.py /app/
COPY api/ /app/api/
COPY api_v1/ /app/api_v1/
COPY utils/ /app/utils/
COPY scripts/ /app/scripts/

# Copy startup scripts
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/healthcheck.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh /healthcheck.sh

# Environment variable defaults
ENV GHIDRA_MCP_HOST=0.0.0.0 \
    GHIDRA_MCP_PORT=8803 \
    GHIDRA_MCP_SSE_PORT=8804 \
    PROJECT_MODE=local \
    PROJECT_PATH=/ghidra-projects \
    PROJECT_NAME=default \
    LOG_LEVEL=INFO \
    LOG_DIR=/app/logs

# Create log directory
RUN mkdir -p /app/logs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s \
  CMD /healthcheck.sh

# Expose ports
EXPOSE 8803 8804

ENTRYPOINT ["/entrypoint.sh"]
