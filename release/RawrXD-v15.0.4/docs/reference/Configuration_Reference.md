# Configuration Reference
## Sovereign IDE Reference Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

Complete reference for Sovereign IDE configuration options.

---

## Configuration Files

| File | Purpose |
|------|---------|
| `sovereign.yml` | Main configuration |
| `analysis.yml` | Analysis settings |
| `ui.yml` | UI preferences |
| `keybindings.yml` | Keyboard shortcuts |

---

## Main Configuration

### Server Section

```yaml
server:
  host: 0.0.0.0
  port: 8080
  
  ssl:
    enabled: true
    cert: /etc/ssl/cert.pem
    key: /etc/ssl/key.pem
    
  cors:
    enabled: true
    origins:
      - https://app.sovereign-ide.io
      
  rate_limit:
    enabled: true
    requests_per_minute: 100
```

### Analysis Section

```yaml
analysis:
  max_concurrent: 10
  timeout: 3600
  
  sandbox:
    enabled: true
    memory_limit: 4GB
    cpu_limit: 2
    timeout: 300
    
  cache:
    enabled: true
    ttl: 86400
    max_size: 10GB
    
  engines:
    symbolic_execution:
      enabled: true
      max_depth: 1000
      max_paths: 10000
      
    vulnerability_scan:
      enabled: true
      severity_threshold: medium
```

### Database Section

```yaml
database:
  type: postgresql
  host: localhost
  port: 5432
  name: sovereign
  user: sovereign
  password: ${DB_PASSWORD}
  
  pool:
    size: 20
    max_overflow: 10
    timeout: 30
```

### Logging Section

```yaml
logging:
  level: info
  format: json
  
  outputs:
    - type: file
      path: /var/log/sovereign/app.log
      rotation: daily
      retention: 30
      
    - type: syslog
      host: localhost
      port: 514
```

---

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SOVEREIGN_CONFIG` | Config file path | `/etc/sovereign/config.yml` |
| `SOVEREIGN_DATA_DIR` | Data directory | `/var/lib/sovereign` |
| `SOVEREIGN_LOG_LEVEL` | Log level | `debug` |
| `SOVEREIGN_LICENSE_KEY` | License key | `XXXX-XXXX-XXXX` |

---

## Summary

Configuration Reference provides:

- ✅ **Complete option list**
- ✅ **Section descriptions**
- ✅ **Default values**
- ✅ **Environment variables**

**Status:** ✅ Complete
