# RawrXD Configuration Guide

Complete guide to configuring RawrXD for optimal performance.

## Configuration File

RawrXD uses JSON configuration files. The default location is:

- **Windows**: `%USERPROFILE%\.rawrxd\config.json`
- **Linux/macOS**: `~/.rawrxd/config.json`

## Configuration Sections

### Server Configuration

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 8080,
    "threads": 4,
    "timeout": 300
  }
}
```

| Option | Description | Default |
|--------|-------------|---------|
| `host` | Bind address | `127.0.0.1` |
| `port` | Port number | `8080` |
| `threads` | HTTP worker threads | `4` |
| `timeout` | Request timeout (seconds) | `300` |

### Inference Configuration

```json
{
  "inference": {
    "context_length": 4096,
    "batch_size": 512,
    "temperature": 0.7,
    "top_p": 0.9,
    "top_k": 40,
    "repeat_penalty": 1.1,
    "presence_penalty": 0.0,
    "frequency_penalty": 0.0
  }
}
```

| Option | Description | Default | Range |
|--------|-------------|---------|-------|
| `context_length` | Maximum context size | `4096` | 512-32768 |
| `batch_size` | Processing batch size | `512` | 1-2048 |
| `temperature` | Sampling temperature | `0.7` | 0.0-2.0 |
| `top_p` | Nucleus sampling | `0.9` | 0.0-1.0 |
| `top_k` | Top-k sampling | `40` | 0-1000 |
| `repeat_penalty` | Repetition penalty | `1.1` | 1.0-2.0 |

### Hardware Configuration

```json
{
  "hardware": {
    "gpu": true,
    "vulkan": true,
    "cuda": false,
    "rocm": false,
    "metal": false,
    "threads": 8,
    "mmap": true,
    "mlock": false
  }
}
```

| Option | Description | Default |
|--------|-------------|---------|
| `gpu` | Enable GPU acceleration | `true` |
| `vulkan` | Use Vulkan backend | `true` |
| `cuda` | Use CUDA backend | `false` |
| `rocm` | Use ROCm backend | `false` |
| `metal` | Use Metal backend (macOS) | `false` |
| `threads` | CPU threads | Auto-detect |
| `mmap` | Memory-map model files | `true` |
| `mlock` | Lock model in memory | `false` |

### Logging Configuration

```json
{
  "logging": {
    "level": "info",
    "file": "~/.rawrxd/logs/rawrxd.log",
    "max_size": "100MB",
    "max_files": 5,
    "format": "json"
  }
}
```

| Option | Description | Default |
|--------|-------------|---------|
| `level` | Log level | `info` |
| `file` | Log file path | - |
| `max_size` | Maximum log size | `100MB` |
| `max_files` | Number of rotated files | `5` |
| `format` | Log format | `json` |

## Environment Variables

Configuration can be overridden using environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `RAWRXD_CONFIG_PATH` | Config file path | `/etc/rawrxd/config.json` |
| `RAWRXD_LOG_LEVEL` | Log level | `debug` |
| `RAWRXD_THREADS` | CPU threads | `8` |
| `RAWRXD_MODEL_PATH` | Default model | `/models/llama.gguf` |
| `RAWRXD_SERVER_PORT` | Server port | `8080` |

## Configuration Examples

### Minimal Configuration

```json
{
  "inference": {
    "context_length": 2048
  },
  "hardware": {
    "threads": 4
  }
}
```

### High-Performance Configuration

```json
{
  "server": {
    "threads": 8
  },
  "inference": {
    "context_length": 8192,
    "batch_size": 1024
  },
  "hardware": {
    "gpu": true,
    "vulkan": true,
    "threads": 16,
    "mmap": true
  }
}
```

### CPU-Only Configuration

```json
{
  "hardware": {
    "gpu": false,
    "vulkan": false,
    "threads": 8,
    "mmap": true
  }
}
```

### Development Configuration

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080
  },
  "logging": {
    "level": "debug",
    "format": "text"
  },
  "inference": {
    "temperature": 0.8
  }
}
```

## Validation

Validate your configuration:

```bash
rawrxd --validate-config
```

Or use the config validator script:

```powershell
.\scripts\config_validator.ps1 -ConfigFile config.json -Strict
```

## Troubleshooting

### Configuration Not Loading

1. Check file path: `~/.rawrxd/config.json`
2. Validate JSON syntax
3. Check file permissions

### Settings Not Applied

1. Restart RawrXD after configuration changes
2. Check for environment variable overrides
3. Verify configuration with `--show-config`

---

*Last updated: 2026-07-13*
