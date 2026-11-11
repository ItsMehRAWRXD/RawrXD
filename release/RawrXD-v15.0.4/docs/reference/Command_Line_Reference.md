# RawrXD Command Line Reference
## Complete CLI Documentation

**Version:** 1.0.0  
**Date:** 2026-07-15  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Global Options](#global-options)
3. [Inference Commands](#inference-commands)
4. [Model Commands](#model-commands)
5. [System Commands](#system-commands)
6. [Development Commands](#development-commands)
7. [Configuration Commands](#configuration-commands)
8. [Examples](#examples)

---

## Overview

Complete reference for RawrXD command line interface.

### Basic Syntax

```bash
rawrxd [global-options] <command> [command-options] [arguments]
```

### Help

```bash
# Show general help
rawrxd --help
rawrxd -h

# Show command help
rawrxd <command> --help
rawrxd infer --help
```

---

## Global Options

| Option | Short | Description |
|--------|-------|-------------|
| `--help` | `-h` | Show help message |
| `--version` | `-v` | Show version information |
| `--verbose` | `-V` | Enable verbose output |
| `--quiet` | `-q` | Suppress output |
| `--config <file>` | `-c` | Specify config file |
| `--log-level <level>` | `-l` | Set log level |
| `--log-file <file>` | | Log to file |
| `--no-color` | | Disable colored output |
| `--json` | `-j` | Output JSON format |

### Log Levels

```bash
# Available levels
rawrxd --log-level=trace    # Most verbose
rawrxd --log-level=debug
rawrxd --log-level=info     # Default
rawrxd --log-level=warning
rawrxd --log-level=error
rawrxd --log-level=fatal    # Least verbose
```

---

## Inference Commands

### infer

Run inference with a model.

```bash
rawrxd infer [options] [prompt]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--model <path>` | Model file path | Required |
| `--prompt <text>` | Input prompt | Required |
| `--prompt-file <file>` | Read prompt from file | - |
| `--max-tokens <n>` | Maximum tokens to generate | 256 |
| `--temperature <float>` | Sampling temperature | 0.8 |
| `--top-p <float>` | Nucleus sampling | 0.95 |
| `--top-k <n>` | Top-k sampling | 40 |
| `--repeat-penalty <float>` | Repetition penalty | 1.1 |
| `--context-size <n>` | Context window size | 4096 |
| `--batch-size <n>` | Batch size | 512 |
| `--threads <n>` | Number of threads | Auto |
| `--gpu-layers <n>` | Layers on GPU | 0 |
| `--stream` | Stream output | false |
| `--output <file>` | Save output to file | - |
| `--format <format>` | Output format (text/json) | text |

**Examples:**

```bash
# Basic inference
rawrxd infer --model model.gguf --prompt "Hello, world!"

# With options
rawrxd infer \
    --model model.gguf \
    --prompt "Explain quantum computing" \
    --max-tokens 1024 \
    --temperature 0.7 \
    --stream

# Read prompt from file
rawrxd infer --model model.gguf --prompt-file query.txt

# Save output
rawrxd infer --model model.gguf --prompt "Hello" --output response.txt

# JSON output
rawrxd infer --model model.gguf --prompt "Hi" --json
```

### chat

Interactive chat mode.

```bash
rawrxd chat [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--model <path>` | Model file |
| `--system <text>` | System prompt |
| `--history <file>` | Load chat history |
| `--save-history <file>` | Save chat history |

**Examples:**

```bash
# Interactive chat
rawrxd chat --model model.gguf

# With system prompt
rawrxd chat --model model.gguf --system "You are a helpful assistant"

# Save conversation
rawrxd chat --model model.gguf --save-history chat.json
```

### server

Start inference server.

```bash
rawrxd server [options]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--model <path>` | Model file | Required |
| `--host <addr>` | Bind address | 127.0.0.1 |
| `--port <n>` | Port number | 8080 |
| `--workers <n>` | Worker threads | 4 |
| `--api-key <key>` | API key for auth | - |
| `--cors` | Enable CORS | false |
| `--ssl-cert <file>` | SSL certificate | - |
| `--ssl-key <file>` | SSL private key | - |

**Examples:**

```bash
# Start server
rawrxd server --model model.gguf

# With custom port
rawrxd server --model model.gguf --port 9000

# With authentication
rawrxd server --model model.gguf --api-key secret123

# HTTPS server
rawrxd server --model model.gguf --ssl-cert cert.pem --ssl-key key.pem
```

---

## Model Commands

### model-info

Display model information.

```bash
rawrxd model-info [options] <model>
```

**Options:**

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON |
| `--vocab-only` | Show vocabulary info only |

**Examples:**

```bash
# Show model info
rawrxd model-info model.gguf

# JSON output
rawrxd model-info model.gguf --json
```

### quantize

Quantize a model.

```bash
rawrxd quantize [options] <input> <output>
```

**Options:**

| Option | Description |
|--------|-------------|
| `--type <type>` | Quantization type (Q4_0, Q4_1, Q5_0, Q5_1, Q8_0) |
| `--threads <n>` | Number of threads |

**Examples:**

```bash
# Quantize to Q4_0
rawrxd quantize --type Q4_0 model.gguf model-q4.gguf

# Quantize to Q8_0 with 8 threads
rawrxd quantize --type Q8_0 --threads 8 model.gguf model-q8.gguf
```

### convert

Convert model format.

```bash
rawrxd convert [options] <input> <output>
```

**Options:**

| Option | Description |
|--------|-------------|
| `--from <format>` | Source format |
| `--to <format>` | Target format |
| `--vocab <file>` | Vocabulary file |

**Examples:**

```bash
# Convert PyTorch to GGUF
rawrxd convert --from pytorch --to gguf model.pt model.gguf

# Convert with custom vocab
rawrxd convert --from safetensors --to gguf model.safetensors model.gguf --vocab vocab.json
```

### download

Download a model.

```bash
rawrxd download [options] <url>
```

**Options:**

| Option | Description |
|--------|-------------|
| `--output <file>` | Output file |
| `--resume` | Resume partial download |
| `--checksum <hash>` | Verify SHA256 checksum |

**Examples:**

```bash
# Download model
rawrxd download https://example.com/model.gguf

# With checksum verification
rawrxd download https://example.com/model.gguf --checksum abc123...
```

---

## System Commands

### benchmark

Run performance benchmark.

```bash
rawrxd benchmark [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--model <path>` | Model to benchmark |
| `--duration <seconds>` | Benchmark duration |
| `--prompt <text>` | Test prompt |
| `--output <file>` | Save results |

**Examples:**

```bash
# Benchmark current setup
rawrxd benchmark

# Benchmark specific model
rawrxd benchmark --model model.gguf

# Extended benchmark
rawrxd benchmark --model model.gguf --duration 60 --output results.json
```

### diagnose

Run system diagnostics.

```bash
rawrxd diagnose [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--full` | Full diagnostic |
| `--gpu` | GPU diagnostics only |
| `--memory` | Memory diagnostics only |
| `--output <file>` | Save report |

**Examples:**

```bash
# Quick diagnostics
rawrxd diagnose

# Full diagnostics
rawrxd diagnose --full

# Save report
rawrxd diagnose --full --output diag.txt
```

### devices

List available devices.

```bash
rawrxd devices [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--json` | JSON output |

**Examples:**

```bash
# List devices
rawrxd devices

# JSON output
rawrxd devices --json
```

---

## Development Commands

### build

Build from source.

```bash
rawrxd build [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--target <target>` | Build target |
| `--config <config>` | Build configuration |
| `--clean` | Clean build |
| `--jobs <n>` | Parallel jobs |

**Examples:**

```bash
# Build default target
rawrxd build

# Release build
rawrxd build --config Release

# Clean build with 8 jobs
rawrxd build --clean --jobs 8
```

### test

Run tests.

```bash
rawrxd test [options] [test-pattern]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--list` | List tests |
| `--verbose` | Verbose output |
| `--filter <pattern>` | Filter tests |
| `--output <file>` | Save results |

**Examples:**

```bash
# Run all tests
rawrxd test

# Run specific tests
rawrxd test "inference*"

# List tests
rawrxd test --list
```

### profile

Profile performance.

```bash
rawrxd profile [options] <command>
```

**Options:**

| Option | Description |
|--------|-------------|
| `--output <file>` | Save profile |
| `--format <format>` | Output format |

**Examples:**

```bash
# Profile inference
rawrxd profile --output profile.json infer --model model.gguf --prompt "test"
```

---

## Configuration Commands

### config

Manage configuration.

```bash
rawrxd config <subcommand> [options]
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `get <key>` | Get config value |
| `set <key> <value>` | Set config value |
| `list` | List all config |
| `reset` | Reset to defaults |
| `path` | Show config file path |

**Examples:**

```bash
# Get config value
rawrxd config get model.default

# Set config value
rawrxd config set model.default /path/to/model.gguf

# List all config
rawrxd config list

# Reset config
rawrxd config reset
```

---

## Examples

### Common Workflows

```bash
# Quick start - download, quantize, and run
rawrxd download https://huggingface.co/model.gguf
rawrxd quantize --type Q4_0 model.gguf model-q4.gguf
rawrxd infer --model model-q4.gguf --prompt "Hello"

# Production server setup
rawrxd quantize --type Q8_0 model.gguf model-q8.gguf
rawrxd server --model model-q8.gguf --port 8080 --workers 8

# Development workflow
rawrxd build --config Debug
rawrxd test --verbose
rawrxd benchmark --output bench.json

# Batch processing
for file in prompts/*.txt; do
    rawrxd infer --model model.gguf --prompt-file "$file" --output "out/$(basename $file)"
done
```

### Environment Variables

```bash
# Configuration
export RAWRXD_CONFIG=/path/to/config.json
export RAWRXD_LOG_LEVEL=debug

# Performance
export RAWRXD_THREADS=16
export RAWRXD_GPU_LAYERS=33

# Paths
export RAWRXD_MODEL_PATH=/models
export RAWRXD_CACHE_PATH=/cache
```

---

## Summary

Command line reference coverage:

- ✅ Global options
- ✅ Inference commands (infer, chat, server)
- ✅ Model commands (info, quantize, convert, download)
- ✅ System commands (benchmark, diagnose, devices)
- ✅ Development commands (build, test, profile)
- ✅ Configuration commands
- ✅ Examples and workflows

**Status:** ✅ Complete

---

*End of Command Line Reference*
