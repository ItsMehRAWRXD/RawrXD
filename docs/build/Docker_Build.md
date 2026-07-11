# Docker Build
## Sovereign IDE Build Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

Docker builds provide reproducible, isolated build environments for the Sovereign IDE.

### Available Images

| Image | Purpose | Size |
|-------|---------|------|
| `sovereign/build` | Build environment | 2 GB |
| `sovereign/dev` | Development | 5 GB |
| `sovereign/runtime` | Runtime only | 500 MB |

---

## Quick Start

### Build with Docker

```bash
# Clone repository
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD

# Build using Docker
docker build -t sovereign-ide .

# Or use docker-compose
docker-compose up --build
```

### Dockerfile

```dockerfile
FROM sovereign/build:latest

WORKDIR /build

# Copy source
COPY . .

# Build
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build --parallel

# Install
RUN cmake --install build --prefix /opt/sovereign

# Runtime image
FROM sovereign/runtime:latest
COPY --from=0 /opt/sovereign /opt/sovereign
ENV PATH="/opt/sovereign/bin:${PATH}"
ENTRYPOINT ["sovereign"]
```

---

## Docker Compose

```yaml
version: '3.8'

services:
  sovereign:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./projects:/projects
    environment:
      - SOVEREIGN_DATA=/data
    
  sovereign-dev:
    image: sovereign/dev:latest
    volumes:
      - .:/workspace
      - /var/run/docker.sock:/var/run/docker.sock
    working_dir: /workspace
    command: /bin/bash
    stdin_open: true
    tty: true
```

---

## Summary

Docker Build provides:

- ✅ **3 image variants**
- ✅ **Reproducible builds**
- ✅ **Multi-stage builds**
- ✅ **Docker Compose**
- ✅ **CI/CD ready**

**Status:** ✅ Complete
