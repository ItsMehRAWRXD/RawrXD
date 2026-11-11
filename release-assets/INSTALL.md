# RawrXD Sovereign v1.0.0 - Installation Guide

## Quick Start

### Windows (x64)

1. Download `RawrXD-Sovereign-Windows-x64.zip`
2. Extract to `C:\Program Files\RawrXD\`
3. Run `install.bat` as Administrator
4. Start RawrXD from Start Menu or run `RawrXD.exe`

```powershell
# Using PowerShell
Invoke-WebRequest -Uri "https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v1.0.0-complete/RawrXD-Sovereign-Windows-x64.zip" -OutFile "RawrXD.zip"
Expand-Archive -Path "RawrXD.zip" -DestinationPath "C:\Program Files\RawrXD"
cd "C:\Program Files\RawrXD"
.\install.bat
```

### Linux (x64)

1. Download `RawrXD-Sovereign-Linux-x64.tar.gz`
2. Extract: `tar -xzf RawrXD-Sovereign-Linux-x64.tar.gz`
3. Run: `sudo ./install.sh`
4. Start: `rawrxd --config /etc/rawrxd/config.yaml`

```bash
# Quick install
curl -fsSL https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v1.0.0-complete/RawrXD-Sovereign-Linux-x64.tar.gz | tar -xz
cd RawrXD-Sovereign
sudo ./install.sh
```

### macOS (Apple Silicon & Intel)

1. Download `RawrXD-Sovereign-macOS.dmg`
2. Open DMG and drag to Applications
3. Allow in System Preferences → Security & Privacy
4. Launch from Applications

### Docker

```bash
# Pull and run
docker pull rawrxd/sovereign:1.0.0
docker run -p 8080:8080 -v $(pwd)/models:/app/models rawrxd/sovereign:1.0.0

# Or use docker-compose
cd release-assets/docker
docker-compose up -d
```

---

## System Requirements

### Minimum
- **OS:** Windows 10/11, Ubuntu 22.04+, macOS 13+
- **CPU:** 4 cores, x86_64 or ARM64
- **RAM:** 16 GB
- **Storage:** 10 GB free space
- **GPU:** Optional (Vulkan 1.3+ or CUDA 12+)

### Recommended
- **CPU:** 8+ cores, AVX2/AVX-512 support
- **RAM:** 32 GB
- **Storage:** NVMe SSD, 50 GB free
- **GPU:** AMD RX 7800 XT (16GB) or NVIDIA RTX 4090 (24GB)

---

## Hardware Compatibility

| GPU | VRAM | Status | Notes |
|-----|------|--------|-------|
| AMD RX 7800 XT | 16GB | ✅ Certified | Primary test platform |
| AMD RX 7900 XTX | 24GB | ✅ Supported | Maximum performance |
| NVIDIA RTX 4090 | 24GB | ✅ Supported | CUDA backend |
| NVIDIA RTX 3090 | 24GB | ✅ Supported | CUDA backend |
| Intel Arc A770 | 16GB | ⚠️ Beta | Vulkan only |
| Apple M3 Max | 36GB | ✅ Supported | Metal backend |

---

## Post-Installation

### 1. Download a Model

```bash
rawrxd pull llama3.1-8b
# or
rawrxd pull hf.co/unsloth/Llama-3.1-8B-GGUF
```

### 2. Verify Installation

```bash
rawrxd --version
rawrxd validate
```

### 3. Run Benchmark

```bash
rawrxd benchmark --model llama3.1-8b --tokens 4096
```

### 4. Start API Server

```bash
rawrxd serve --host 0.0.0.0 --port 8080
```

---

## Configuration

Edit `config.yaml`:

```yaml
server:
  host: 0.0.0.0
  port: 8080

models:
  directory: ~/.rawrxd/models
  default: llama3.1-8b

gpu:
  enabled: true
  layers: -1  # Auto-detect

security:
  auth_enabled: true
  api_key: ${RAWRXD_API_KEY}
```

---

## Troubleshooting

### "Vulkan not found"
Install Vulkan drivers for your GPU.

### "Out of memory"
Reduce GPU layers or use Q4 quantization.

### "Permission denied (Linux)"
Run: `sudo usermod -aG render,video $USER`

### "Model loading fails"
Verify model file integrity: `sha256sum model.gguf`

---

## Support

- Documentation: https://docs.rawrxd.local
- Issues: https://github.com/ItsMehRAWRXD/RawrXD/issues
- Discord: https://discord.gg/rawrxd
- Email: support@rawrxd.local

---

**Version:** 1.0.0-complete  
**Release Date:** 2026-07-13  
**License:** MIT
