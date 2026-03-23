# Ghidra MCP Bridge
# Uses Ghidra 12.0+ with native PyGhidra support

FROM eclipse-temurin:23-jdk AS base

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    netcat-openbsd \
    openssh-client \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Download and install Ghidra 12.0.3
ENV GHIDRA_VERSION=12.0.3
ENV GHIDRA_BUILD_DATE=20260210
ENV GHIDRA_SHA=ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD_DATE}.zip
ENV GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_SHA}

WORKDIR /opt

# Download Ghidra
RUN wget -q ${GHIDRA_URL} && \
    unzip -q ${GHIDRA_SHA} && \
    rm ${GHIDRA_SHA} && \
    mv ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra && \
    chmod +x /opt/ghidra/support/analyzeHeadless

# Set Ghidra environment
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV PATH="${GHIDRA_INSTALL_DIR}/support:${PATH}"

# Install Python dependencies
COPY requirements.txt /tmp/
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt && \
    pip3 install --no-cache-dir --break-system-packages pyghidra

# Set working directory
WORKDIR /app

# Copy source code
COPY ghidra_mcp_server_pyghidra.py /app/
COPY api/ /app/api/
COPY api_v1/ /app/api_v1/
COPY utils/ /app/utils/
COPY scripts/ /app/scripts/

# Copy startup scripts
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/healthcheck.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh /healthcheck.sh

# Copy custom server.conf (without strict cipher suite restriction)
COPY docker/server.conf /opt/ghidra/server/server.conf

# Environment variable defaults
ENV GHIDRA_MCP_HOST=0.0.0.0 \
    GHIDRA_MCP_PORT=8803 \
    GHIDRA_MCP_SSE_PORT=8804 \
    PROJECT_MODE=local \
    PROJECT_PATH=/ghidra-projects \
    PROJECT_NAME=default \
    LOG_LEVEL=INFO \
    LOG_DIR=/app/logs \
    PYTHONUNBUFFERED=1

# Create log directory
RUN mkdir -p /app/logs /ghidra-projects /repos /ssh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s \
  CMD /healthcheck.sh

# Expose ports
EXPOSE 8803 8804

ENTRYPOINT ["/entrypoint.sh"]
