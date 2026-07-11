# Error Codes
## Sovereign IDE Reference Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

Complete reference for Sovereign IDE error codes and their meanings.

---

## Error Code Format

Error codes follow the format: `SOV-XXX-YYYY`

| Component | Meaning |
|-----------|---------|
| `SOV` | Sovereign prefix |
| `XXX` | Category code |
| `YYYY` | Specific error |

---

## Categories

| Code | Category |
|------|----------|
| `100` | General |
| `200` | Analysis |
| `300` | Binary Loading |
| `400` | Network |
| `500` | Database |
| `600` | Configuration |
| `700` | License |
| `800` | Plugin |
| `900` | System |

---

## General Errors (100)

| Code | Message | Description |
|------|---------|-------------|
| `SOV-100-0001` | Unknown error | Unspecified error occurred |
| `SOV-100-0002` | Invalid argument | Invalid parameter provided |
| `SOV-100-0003` | Out of memory | System ran out of memory |
| `SOV-100-0004` | Permission denied | Insufficient permissions |
| `SOV-100-0005` | Not implemented | Feature not yet implemented |

## Analysis Errors (200)

| Code | Message | Description |
|------|---------|-------------|
| `SOV-200-0001` | Analysis failed | General analysis failure |
| `SOV-200-0002` | Timeout exceeded | Analysis took too long |
| `SOV-200-0003` | Invalid binary | Binary format not recognized |
| `SOV-200-0004` | Unsupported arch | Architecture not supported |
| `SOV-200-0005` | Sandbox error | Sandbox execution failed |

## Binary Loading Errors (300)

| Code | Message | Description |
|------|---------|-------------|
| `SOV-300-0001` | File not found | Binary file does not exist |
| `SOV-300-0002` | Access denied | Cannot read binary file |
| `SOV-300-0003` | Invalid format | File is not a valid binary |
| `SOV-300-0004` | Corrupted file | Binary file is corrupted |
| `SOV-300-0005` | Unsupported format | Binary format not supported |

## Network Errors (400)

| Code | Message | Description |
|------|---------|-------------|
| `SOV-400-0001` | Connection failed | Cannot connect to server |
| `SOV-400-0002` | Timeout | Network request timed out |
| `SOV-400-0003` | Invalid response | Server returned invalid data |
| `SOV-400-0004` | SSL error | SSL/TLS handshake failed |
| `SOV-400-0005` | Rate limited | Too many requests |

## Database Errors (500)

| Code | Message | Description |
|------|---------|-------------|
| `SOV-500-0001` | Connection failed | Cannot connect to database |
| `SOV-500-0002` | Query failed | Database query failed |
| `SOV-500-0003` | Constraint violation | Data constraint violated |
| `SOV-500-0004` | Not found | Record not found |
| `SOV-500-0005` | Migration failed | Database migration failed |

## Configuration Errors (600)

| Code | Message | Description |
|------|---------|-------------|
| `SOV-600-0001` | Invalid config | Configuration file invalid |
| `SOV-600-0002` | Missing option | Required option missing |
| `SOV-600-0003` | Invalid value | Configuration value invalid |
| `SOV-600-0004` | File not found | Configuration file not found |

## License Errors (700)

| Code | Message | Description |
|------|---------|-------------|
| `SOV-700-0001` | Invalid license | License key invalid |
| `SOV-700-0002` | Expired | License has expired |
| `SOV-700-0003` | Limit exceeded | License limit exceeded |
| `SOV-700-0004` | Not activated | License not activated |

## Plugin Errors (800)

| Code | Message | Description |
|------|---------|-------------|
| `SOV-800-0001` | Load failed | Failed to load plugin |
| `SOV-800-0002` | Incompatible | Plugin version incompatible |
| `SOV-800-0003` | Dependency missing | Required dependency missing |
| `SOV-800-0004` | Init failed | Plugin initialization failed |

## System Errors (900)

| Code | Message | Description |
|------|---------|-------------|
| `SOV-900-0001` | Internal error | Internal system error |
| `SOV-900-0002` | Resource exhausted | System resources exhausted |
| `SOV-900-0003` | Service unavailable | Service temporarily unavailable |

---

## Summary

Error Codes provides:

- ✅ **Complete error code list**
- ✅ **Category organization**
| ✅ **Error descriptions** |
| ✅ **Troubleshooting guidance** |

**Status:** ✅ Complete
