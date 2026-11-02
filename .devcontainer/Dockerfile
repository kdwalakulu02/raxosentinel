FROM mcr.microsoft.com/devcontainers/base:trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates git-lfs pkg-config \
    && rm -rf /var/lib/apt/lists/*
