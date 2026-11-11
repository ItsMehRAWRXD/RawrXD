# RawrXD Installation Guide

Quick installation instructions for RawrXD Sovereign Inferencer.

## System Requirements

### Minimum Requirements
- **OS**: Windows 10/11, Ubuntu 20.04+, macOS 12+
- **CPU**: x64 with AVX2 support
- **RAM**: 8 GB
- **Storage**: 2 GB free space
- **GPU**: Optional (for acceleration)

### Recommended Requirements
- **OS**: Windows 11, Ubuntu 22.04+, macOS 13+
- **CPU**: x64 with AVX-512 support
- **RAM**: 32 GB
- **Storage**: 10 GB free space (for models)
- **GPU**: NVIDIA RTX 3060+ or AMD RX 6600+ with 8GB+ VRAM

## Quick Install

### Windows

#### Option 1: Installer (Recommended)

1. Download `RawrXD-v14.7.3-win64.exe` from [releases](https://github.com/ItsMehRAWRXD/RawrXD/releases)
2. Run the installer
3. Follow the setup wizard
4. Launch RawrXD from Start Menu

#### Option 2: Portable

1. Download `RawrXD-v14.7.3-win64.zip`
2. Extract to desired location
3. Run `bin\rawrxd.exe`

#### Option 3: Winget

```powershell
winget install RawrXD.RawrXD
```

### Linux

#### Ubuntu/Debian

```bash
# Download and install
wget https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v14.7.3/rawrxd_14.7.3_amd64.deb
sudo dpkg -i rawrxd_14.7.3_amd64.deb

# Start service
sudo systemctl enable --now rawrxd
```

#### Fedora/RHEL

```bash
# Download and install
sudo rpm -i https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v14.7.3/rawrxd-14.7.3.x86_64.rpm

# Start service
sudo systemctl enable --now rawrxd
```

#### Generic (tar.gz)

```bash
# Download
curl -L -o rawrxd.tar.gz https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v14.7.3/RawrXD-v14.7.3-linux.tar.gz

# Extract
tar -xzf rawrxd.tar.gz
cd RawrXD-v14.7.3-linux

# Run
./bin/rawrxd
```

### macOS

```bash
# Using Homebrew
brew tap rawrxd/tap
brew install rawrxd

# Or download directly
curl -L -o rawrxd.dmg https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v14.7.3/RawrXD-v14.7.3-macos.dmg
open rawrxd.dmg
```

## Post-Installation

### 1. Configure

Edit `config/default.json` or set environment variables:

```bash
# Linux/macOS
export RAWRXD_SERVER_PORT=8080
export RAWRXD_MODELS_DIRECTORY=/path/to/models

# Windows PowerShell
$env:RAWRXD_SERVER_PORT = 8080
$env:RAWRXD_MODELS_DIRECTORY = "C:\Models"
```

### 2. Download Models

```bash
# Using the model downloader
rawrxd model download llama-3.2-3b

# Or manually place .gguf files in models/ directory
```

### 3. Start Server

```bash
# Start with default config
rawrxd

# Start with custom config
rawrxd --config /path/to/config.json

# Start with specific model
rawrxd --model llama-3.2-3b
```

### 4. Verify Installation

```bash
# Check version
rawrxd --version

# Check health
curl http://localhost:8080/health

# Test inference
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "llama-3.2-3b", "messages": [{"role": "user", "content": "Hello"}]}'
```

## Docker Installation

```bash
# Pull image
docker pull rawrxd/rawrxd:latest

# Run
docker run -d \
  -p 8080:8080 \
  -v /path/to/models:/models \
  -e RAWRXD_MODELS_DIRECTORY=/models \
  rawrxd/rawrxd:latest
```

## GPU Support

### NVIDIA (CUDA)

```bash
# Install CUDA drivers first
# Then run with GPU support
rawrxd --gpu-layers 35
```

### AMD (ROCm)

```bash
# Install ROCm drivers first
# Then run with GPU support
rawrxd --gpu-layers 35 --backend rocm
```

### Vulkan (Cross-platform)

```bash
# Install Vulkan drivers
# Then run with Vulkan backend
rawrxd --backend vulkan
```

## Troubleshooting

### Port Already in Use

```bash
# Use different port
rawrxd --port 8081
```

### Out of Memory

```bash
# Reduce context size
rawrxd --max-context-length 2048

# Or use memory-mapped files
rawrxd --use-mmap
```

### Model Not Found

```bash
# Verify model path
rawrxd --models-dir /path/to/models --list-models
```

### Permission Denied (Linux)

```bash
# Fix permissions
sudo chown -R $USER:$USER ~/.config/rawrxd
```

## Uninstallation

### Windows

```powershell
# Using winget
winget uninstall RawrXD.RawrXD

# Or Control Panel > Programs and Features
```

### Linux

```bash
# Ubuntu/Debian
sudo apt remove rawrxd

# Fedora/RHEL
sudo rpm -e rawrxd

# Generic
sudo rm -rf /opt/rawrxd
```

### macOS

```bash
# Homebrew
brew uninstall rawrxd

# Manual
sudo rm -rf /Applications/RawrXD.app
```

## Getting Help

- **Documentation**: https://docs.rawrxd.ai
- **GitHub Issues**: https://github.com/ItsMehRAWRXD/RawrXD/issues
- **Discord**: https://discord.gg/rawrxd
- **Email**: support@rawrxd.ai

## License

RawrXD is licensed under the MIT License. See LICENSE file for details.
