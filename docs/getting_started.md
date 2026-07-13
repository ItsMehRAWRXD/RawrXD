# Getting Started with RawrXD

Welcome to RawrXD - The Sovereign Inferencer! This guide will help you get up and running quickly.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Basic Usage](#basic-usage)
4. [Configuration](#configuration)
5. [Next Steps](#next-steps)

## Installation

### Windows

```powershell
# Download the latest release
Invoke-WebRequest -Uri "https://github.com/ItsMehRAWRXD/RawrXD/releases/latest/download/RawrXD-win64.zip" -OutFile "rawrxd.zip"

# Extract
Expand-Archive -Path "rawrxd.zip" -DestinationPath "C:\Program Files\RawrXD"

# Add to PATH
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\RawrXD\bin", "User")
```

### Linux

```bash
# Download
wget https://github.com/ItsMehRAWRXD/RawrXD/releases/latest/download/RawrXD-linux-x64.tar.gz

# Extract and install
tar -xzf RawrXD-linux-x64.tar.gz
sudo cp -r RawrXD /opt/
sudo ln -s /opt/RawrXD/bin/rawrxd /usr/local/bin/rawrxd
```

### macOS

```bash
# Using Homebrew (coming soon)
brew install rawrxd

# Or manual installation
wget https://github.com/ItsMehRAWRXD/RawrXD/releases/latest/download/RawrXD-macos-x64.tar.gz
tar -xzf RawrXD-macos-x64.tar.gz
sudo cp -r RawrXD /usr/local/
```

## Quick Start

### Verify Installation

```bash
# Check version
rawrxd --version

# Show help
rawrxd --help
```

### Download a Model

```bash
# Download a model from Hugging Face
rawrxd --download "TheBloke/Llama-2-7B-GGUF" --output models/
```

### Run Inference

```bash
# Basic usage
rawrxd -m models/llama-2-7b.Q4_0.gguf -p "Hello, how are you?"

# With more tokens
rawrxd -m models/llama-2-7b.Q4_0.gguf -p "Explain quantum computing" -n 512

# Interactive mode
rawrxd -m models/llama-2-7b.Q4_0.gguf --interactive
```

## Basic Usage

### Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-m, --model` | Path to model file | `-m model.gguf` |
| `-p, --prompt` | Input prompt | `-p "Hello"` |
| `-n, --n-predict` | Number of tokens to generate | `-n 256` |
| `-t, --threads` | Number of CPU threads | `-t 8` |
| `-c, --ctx-size` | Context size | `-c 4096` |
| `--temp` | Temperature | `--temp 0.7` |
| `--top-p` | Top-p sampling | `--top-p 0.9` |
| `--top-k` | Top-k sampling | `--top-k 40` |

### Examples

```bash
# Creative writing (higher temperature)
rawrxd -m model.gguf -p "Write a story about" --temp 0.9 -n 500

# Factual response (lower temperature)
rawrxd -m model.gguf -p "What is the capital of France?" --temp 0.2

# Code generation
rawrxd -m model.gguf -p "Write a Python function to sort a list" --temp 0.4

# Chat format
rawrxd -m model.gguf -p "User: Hello\nAssistant:" --temp 0.7
```

## Configuration

### Configuration File

Create `~/.rawrxd/config.json`:

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 8080,
    "threads": 4
  },
  "inference": {
    "context_length": 4096,
    "batch_size": 512,
    "temperature": 0.7,
    "top_p": 0.9,
    "top_k": 40
  },
  "hardware": {
    "gpu": true,
    "vulkan": true,
    "cuda": false,
    "threads": 8
  },
  "logging": {
    "level": "info",
    "file": "~/.rawrxd/logs/rawrxd.log"
  }
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RAWRXD_CONFIG_PATH` | Path to config file | `~/.rawrxd/config.json` |
| `RAWRXD_LOG_LEVEL` | Logging level | `info` |
| `RAWRXD_THREADS` | Number of threads | Auto-detect |
| `RAWRXD_MODEL_PATH` | Default model path | - |

## Next Steps

- [API Documentation](api_reference.md) - Learn about the REST API
- [Configuration Guide](configuration.md) - Advanced configuration options
- [Performance Tuning](performance.md) - Optimize for your hardware
- [Troubleshooting](troubleshooting.md) - Common issues and solutions

## Support

- GitHub Issues: https://github.com/ItsMehRAWRXD/RawrXD/issues
- Documentation: https://rawrxd.dev/docs
- Community Discord: https://discord.gg/rawrxd

---

*Last updated: 2026-07-13*
