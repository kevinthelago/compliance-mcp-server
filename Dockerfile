# syntax=docker/dockerfile:1
# Compliance MCP Server — bundles semgrep, trivy, syft, gitleaks
FROM python:3.12-slim AS base

# System deps required by scanner install scripts
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    wget \
    ca-certificates \
    tar \
    && rm -rf /var/lib/apt/lists/*

# --- semgrep ---
RUN pip install semgrep --no-cache-dir

# --- trivy ---
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin v0.51.0

# --- syft ---
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin v1.4.1

# --- gitleaks ---
RUN curl -sSfL \
    https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks

# Install the compliance-mcp-server package
WORKDIR /app
COPY pyproject.toml compliance.toml ./
COPY src/ src/
COPY policies/ policies/

RUN pip install --no-cache-dir uv \
    && uv pip install --system -e . --no-cache

# Verify all four scanner binaries are on PATH
RUN semgrep --version && trivy --version && syft --version && gitleaks version

# Run as non-root
RUN useradd -m -u 1000 mcp
USER mcp

# MCP stdio server — clients connect via stdin/stdout
ENTRYPOINT ["compliance-mcp"]
