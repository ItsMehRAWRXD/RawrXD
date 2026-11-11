# Installation Guide

## Phase J.2/5: User Guides - Installation

This guide covers installing RawrXD Sovereign AI Runtime on various platforms.

## System Requirements

### Minimum Requirements
- **OS**: Windows 10/11 (64-bit) or Ubuntu 20.04+
- **CPU**: AMD Ryzen 5 or Intel Core i5 (AVX2 support)
- **RAM**: 16 GB
- **GPU**: AMD RX 6600 / NVIDIA GTX 1060 / 8GB VRAM
- **Storage**: 50 GB free space

### Recommended Requirements
- **OS**: Windows 11 or Ubuntu 22.04
- **CPU**: AMD Ryzen 7/9 or Intel Core i7/i9
- **RAM**: 32 GB
- **GPU**: AMD RX 7800 XT / NVIDIA RTX 4070 / 16GB VRAM
- **Storage**: 100 GB SSD

## Windows Installation

### Method 1: Pre-built Binary

1. Download the latest release from GitHub:
   ```powershell
   # Download using PowerShell
   Invoke-WebRequest -Uri "https://github.com/ItsMehRAWRXD/RawrXD/releases/latest/download/rawrxd-windows.zip" -OutFile "rawrxd.zip"
   ```

2. Extract the archive:
   ```powershell
   Expand-Archive -Path "rawrxd.zip" -DestinationPath "C:\Program Files\RawrXD"
   ```

3. Add to PATH:
   ```powershell
   [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\RawrXD\bin", "Machine")
   ```

4. Verify installation:
   ```powershell
   rawrxd --version
   ```

### Method 2: Build from Source

**Prerequisites:**
- Visual Studio 2022 with C++ workload
- CMake 3.20+
- Vulkan SDK 1.3+
- Python 3.9+

**Build Steps:**

1. Clone the repository:
   ```powershell
   git clone --recursive https://github.com/ItsMehRAWRXD/RawrXD.git
   cd RawrXD
   ```

2. Configure build:
   ```powershell
   cmake -B build -G "Visual Studio 17 2022" -A x64 `
     -DCMAKE_BUILD_TYPE=Release `
     -DRAWRXD_ENABLE_VULKAN=ON
   ```

3. Build:
   ```powershell
   cmake --build build --config Release --parallel
   ```

4. Install:
   ```powershell
   cmake --install build --prefix "C:\Program Files\RawrXD"
   ```

## Linux Installation

### Ubuntu/Debian

1. Install dependencies:
   ```bash
   sudo apt update
   sudo apt install -y build-essential cmake git ninja-build
   sudo apt install -y vulkan-sdk libvulkan-dev
   ```

2. Download and install:
   ```bash
   wget https://github.com/ItsMehRAWRXD/RawrXD/releases/latest/download/rawrxd-linux.tar.gz
   tar -xzf rawrxd-linux.tar.gz
   sudo cp -r rawrxd /opt/
   sudo ln -s /opt/rawrxd/bin/rawrxd /usr/local/bin/rawrxd
   ```

3. Verify:
   ```bash
   rawrxd --version
   ```

### Build from Source

```bash
# Clone
git clone --recursive https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD

# Configure
cmake -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DRAWRXD_ENABLE_VULKAN=ON

# Build
cmake --build build --parallel

# Install
sudo cmake --install build --prefix /usr/local
```

## Docker Installation

### Quick Start

```bash
# Pull image
docker pull rawrxd/runtime:latest

# Run
docker run -p 8080:8080 rawrxd/runtime:latest
```

### With GPU Support

```bash
# NVIDIA GPU
docker run --gpus all -p 8080:8080 rawrxd/runtime:cuda-latest

# AMD GPU (ROCm)
docker run --device /dev/kfd --device /dev/dri -p 8080:8080 rawrxd/runtime:rocm-latest
```

## Kubernetes Installation

### Using Helm

1. Add Helm repository:
   ```bash
   helm repo add rawrxd https://charts.rawrxd.ai
   helm repo update
   ```

2. Install:
   ```bash
   helm install rawrxd rawrxd/rawrxd \
     --set gpu.enabled=true \
     --set resources.limits.memory=16Gi
   ```

3. Verify:
   ```bash
   kubectl get pods -l app.kubernetes.io/name=rawrxd
   ```

## Post-Installation

### Download Models

```bash
# Download a model
rawrxd model download microsoft/phi-3-mini

# List available models
rawrxd model list
```

### Configuration

Create configuration file at `~/.rawrxd/config.json`:

```json
{
  "server": {
    "port": 8080,
    "host": "0.0.0.0"
  },
  "model": {
    "default": "phi-3-mini",
    "cache_dir": "~/.rawrxd/models"
  },
  "gpu": {
    "enabled": true,
    "memory_fraction": 0.9
  }
}
```

### Start Service

```bash
# Start server
rawrxd server --config ~/.rawrxd/config.json

# Test
 curl http://localhost:8080/health
```

## Troubleshooting

### Vulkan Not Found

**Windows:**
```powershell
# Install Vulkan SDK from LunarG
# https://vulkan.lunarg.com/sdk/home
```

**Linux:**
```bash
sudo apt install vulkan-tools
vulkaninfo  # Verify installation
```

### Out of Memory

Reduce GPU memory fraction in config:
```json
{
  "gpu": {
    "memory_fraction": 0.7
  }
}
```

### Slow Performance

Enable optimizations:
```bash
rawrxd server --enable-kernel-fusion --optimize-memory-layout
```

## Next Steps

- [Configuration Guide](./configuration.md)
- [Usage Guide](./usage.md)
- [API Reference](../api/openapi.yaml)
