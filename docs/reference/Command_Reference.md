# Command Reference
## Sovereign IDE Reference Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

Complete reference for Sovereign IDE CLI commands.

---

## Global Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help |
| `-v, --version` | Show version |
| `-c, --config` | Config file path |
| `-q, --quiet` | Suppress output |
| `--verbose` | Verbose output |

---

## Commands

### analyze

Analyze a binary file.

**Usage:**
```bash
sovereign analyze [options] <binary>
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `-t, --type` | Analysis type | full |
| `-o, --output` | Output file | stdout |
| `-f, --format` | Output format | json |
| `--timeout` | Timeout (seconds) | 3600 |
| `--depth` | Analysis depth | 10 |

**Examples:**
```bash
# Basic analysis
sovereign analyze binary.exe

# Full analysis with SARIF output
sovereign analyze -t full -f sarif -o results.sarif binary.exe

# Quick analysis with timeout
sovereign analyze --timeout 300 --depth 5 binary.exe
```

### disassemble

Disassemble binary code.

**Usage:**
```bash
sovereign disassemble [options] <binary>
```

**Options:**
| Option | Description |
|--------|-------------|
| `-a, --address` | Start address |
| `-s, --size` | Number of instructions |
| `-f, --function` | Function name |

**Examples:**
```bash
# Disassemble entire binary
sovereign disassemble binary.exe

# Disassemble specific function
sovereign disassemble -f main binary.exe

# Disassemble at address
sovereign disassemble -a 0x401000 -s 100 binary.exe
```

### decompile

Decompile binary to pseudo-code.

**Usage:**
```bash
sovereign decompile [options] <binary>
```

**Options:**
| Option | Description |
|--------|-------------|
| `-f, --function` | Function to decompile |
| `-o, --output` | Output file |

**Examples:**
```bash
# Decompile entire binary
sovereign decompile binary.exe

# Decompile specific function
sovereign decompile -f main -o main.c binary.exe
```

### server

Start Sovereign IDE server.

**Usage:**
```bash
sovereign server [options]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `-p, --port` | Port number | 8080 |
| `-h, --host` | Host address | 0.0.0.0 |
| `--ssl-cert` | SSL certificate | |
| `--ssl-key` | SSL key | |

**Examples:**
```bash
# Start server on default port
sovereign server

# Start with custom port
sovereign server -p 9000

# Start with SSL
sovereign server --ssl-cert cert.pem --ssl-key key.pem
```

---

## Summary

Command Reference provides:

- ✅ **Complete command list**
- ✅ **Option descriptions**
- ✅ **Usage examples**
- ✅ **Default values**

**Status:** ✅ Complete
