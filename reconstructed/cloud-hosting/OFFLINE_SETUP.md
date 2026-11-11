# Offline & Local Setup Guide

## The Absolute Bestest Local AI Experience! 🚀

This guide helps you run RawrXD Quantum Models completely **offline and locally** - no cloud required, no internet needed (after initial setup). Everything runs on your own machine with full control and privacy.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Platform-Specific Installation](#platform-specific-installation)
3. [Offline Model Management](#offline-model-management)
4. [Advanced Configuration](#advanced-configuration)
5. [Troubleshooting](#troubleshooting)
6. [Performance Tuning](#performance-tuning)

---

## Quick Start

### The Fastest Way to Get Started

**Linux/macOS:**
```bash
# Download and run installer
./install-local.sh

# Start the server
rawrxd-serve
```

**Windows:**
```batch
# Double-click install-local.bat
# OR run from PowerShell:
.\install-local.bat

# Start the server
rawrxd-serve.bat
```

That's it! The server will be running at `http://localhost:8080`

---

## Platform-Specific Installation

### Linux

#### Prerequisites
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential cmake git curl wget

# Fedora/RHEL
sudo dnf install -y gcc gcc-c++ cmake git curl wget

# Arch Linux
sudo pacman -Sy base-devel cmake git curl wget
```

#### Install
```bash
chmod +x install-local.sh
./install-local.sh
```

#### Features Included
- ✅ Native binary compilation
- ✅ GPU acceleration (CUDA/ROCm if available)
- ✅ Systemd service (optional)
- ✅ Auto-start on boot
- ✅ Optimized for your CPU

### macOS

#### Prerequisites
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install build tools
brew install cmake git curl wget
```

#### Install
```bash
chmod +x install-local.sh
./install-local.sh
```

#### Features Included
- ✅ Native Apple Silicon (M1/M2/M3) optimization
- ✅ Metal GPU acceleration
- ✅ Menu bar integration (coming soon)
- ✅ macOS-optimized performance

### Windows

#### Prerequisites
1. **Visual Studio 2019 or later** with C++ tools
   - Download: https://visualstudio.microsoft.com/downloads/
   - OR install Build Tools: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022

2. **CMake**
   - Download: https://cmake.org/download/
   - Add to PATH during installation

3. **Git for Windows**
   - Download: https://git-scm.com/download/win

#### Install
```batch
# Right-click install-local.bat → Run as Administrator
.\install-local.bat
```

#### Features Included
- ✅ Native Windows binary
- ✅ CUDA GPU acceleration (if NVIDIA GPU present)
- ✅ Desktop shortcut
- ✅ System tray integration (coming soon)
- ✅ Windows Service option

---

## Offline Model Management

### Using the Model Manager

The model manager helps you download and organize models for offline use:

```bash
# List available models
./model-manager.sh list

# Download a model
./model-manager.sh download phi-2-q4

# View installed models
./model-manager.sh usage

# Verify model integrity
./model-manager.sh verify phi-2.Q4_K_M.gguf

# Remove a model
./model-manager.sh remove phi-2.Q4_K_M.gguf
```

### Available Models

| Model ID | Size | Description | Best For |
|----------|------|-------------|----------|
| `tinyllama-q4` | 669MB | TinyLlama 1.1B | Fast testing, low-end hardware |
| `phi-2-q4` | 1.6GB | Phi-2 2.7B | General purpose, good quality |
| `llama2-7b-q4` | 4.1GB | Llama 2 7B | High quality chat |
| `mistral-7b-q4` | 4.4GB | Mistral 7B | Best 7B model |
| `llama2-13b-q4` | 7.4GB | Llama 2 13B | Professional use |
| `mixtral-8x7b-q4` | 26GB | Mixtral 8x7B | Highest quality |

### Manual Model Installation

1. **Download a GGUF model** from HuggingFace:
   - Search: https://huggingface.co/models?other=gguf
   - Popular: TheBloke's quantized models

2. **Place in models directory:**
   - Linux/macOS: `~/.local/share/rawrxd/models/`
   - Windows: `%USERPROFILE%\RawrXD\models\`

3. **Restart server** - it will automatically detect new models

### Offline Operation

Once models are downloaded:
- ✅ **No internet required**
- ✅ All inference runs locally
- ✅ Complete privacy - nothing leaves your machine
- ✅ Works on planes, trains, anywhere!

---

## Advanced Configuration

### Server Configuration

Create a config file for custom settings:

**Linux/macOS:** `~/.local/share/rawrxd/config.env`
```bash
# Server settings
HOST=0.0.0.0
PORT=8080

# Performance
THREADS=8
CONTEXT_SIZE=4096
BATCH_SIZE=512

# GPU
GPU_LAYERS=32  # Number of layers to offload to GPU

# Memory
MLOCK=1  # Lock model in RAM (prevents swapping)
```

**Windows:** `%USERPROFILE%\RawrXD\config.env`
```batch
# Same format as above
```

### Advanced Startup Options

```bash
# Use specific model
rawrxd-serve --model /path/to/model.gguf

# Adjust threads
rawrxd-serve --threads 16

# Increase context size
rawrxd-serve --ctx-size 8192

# GPU offloading (CUDA)
rawrxd-serve --n-gpu-layers 32

# Multiple models (experimental)
rawrxd-serve --model model1.gguf --model model2.gguf
```

### Running as a Service

**Linux (systemd):**
```bash
# Enable auto-start
systemctl --user enable rawrxd

# Start now
systemctl --user start rawrxd

# Check status
systemctl --user status rawrxd

# View logs
journalctl --user -u rawrxd -f
```

**macOS (launchd):**
```bash
# Create launch agent (coming soon)
# Will auto-start on login
```

**Windows (Service):**
```batch
# Install as Windows Service (requires admin)
sc create RawrXD binPath= "C:\Users\YourName\RawrXD\bin\rawrxd-serve.bat"
sc start RawrXD
```

---

## Troubleshooting

### Common Issues

#### Server Won't Start

**Problem:** Port 8080 already in use

**Solution:**
```bash
# Check what's using port 8080
lsof -i :8080  # Linux/macOS
netstat -ano | findstr :8080  # Windows

# Use different port
rawrxd-serve --port 8081
```

#### Out of Memory

**Problem:** Model too large for RAM

**Solutions:**
1. Use smaller quantized model (Q4 instead of Q8)
2. Close other applications
3. Increase swap space (Linux)
4. Use GPU offloading if available

```bash
# Check available memory
free -h  # Linux
vm_stat  # macOS
wmic OS get FreePhysicalMemory  # Windows
```

#### Slow Performance

**Problem:** Inference is too slow

**Solutions:**
1. Enable GPU acceleration
2. Increase threads: `--threads $(nproc)`
3. Use quantized models (Q4_K_M recommended)
4. Reduce context size: `--ctx-size 2048`

#### Model Not Found

**Problem:** Server can't find models

**Solution:**
```bash
# Verify model location
ls ~/.local/share/rawrxd/models/  # Linux/macOS
dir %USERPROFILE%\RawrXD\models\  # Windows

# Specify model explicitly
rawrxd-serve --model /full/path/to/model.gguf
```

### Debug Mode

Enable verbose logging:
```bash
# Linux/macOS
DEBUG=1 rawrxd-serve

# Windows
set DEBUG=1
rawrxd-serve.bat
```

### Getting Help

1. **Check logs:**
   - Linux/macOS: `~/.local/share/rawrxd/logs/server.log`
   - Windows: `%USERPROFILE%\RawrXD\logs\server.log`

2. **Test API:**
   ```bash
   curl http://localhost:8080/health
   ```

3. **Verify installation:**
   ```bash
   llama-server --version
   ```

---

## Performance Tuning

### CPU Optimization

```bash
# Use all available cores
rawrxd-serve --threads $(nproc)

# Optimize for specific CPU
# Intel
export CFLAGS="-march=native -O3"
# AMD
export CFLAGS="-march=native -O3"
```

### GPU Acceleration

**NVIDIA (CUDA):**
```bash
# Install CUDA toolkit
# Ubuntu: sudo apt install nvidia-cuda-toolkit
# Then rebuild with CUDA support

# Offload layers to GPU
rawrxd-serve --n-gpu-layers 32
```

**AMD (ROCm):**
```bash
# Install ROCm
# Follow: https://rocmdocs.amd.com/

# Rebuild with ROCm support
# GPU offloading enabled automatically
```

**Apple Silicon (Metal):**
```bash
# Automatically enabled on macOS
# Metal acceleration built-in
```

### Memory Management

```bash
# Lock model in RAM (prevents swapping)
rawrxd-serve --mlock

# Reduce memory usage
rawrxd-serve --low-vram
```

### Benchmarking

```bash
# Test inference speed
curl -X POST http://localhost:8080/v1/completions \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Test", "n_predict": 100}' \
  -w "\nTime: %{time_total}s\n"
```

---

## Comparison: Cloud vs Local

| Feature | Cloud (DigitalOcean) | Local (This Guide) |
|---------|---------------------|---------------------|
| Cost | $12-30/month | **Free** (after hardware) |
| Privacy | Data sent to cloud | **100% Private** |
| Internet | Required | **Optional** (offline mode) |
| Latency | 50-200ms | **<10ms** |
| Customization | Limited | **Full Control** |
| GPU | Cloud GPU ($$$) | **Your GPU** |
| Setup Time | 10 minutes | 15-30 minutes |
| Best For | Production, sharing | Personal use, development |

---

## Next Steps

1. **Download more models** - Experiment with different sizes
2. **Integrate with tools** - Use with VSCode, Obsidian, etc.
3. **Build applications** - Create custom AI apps using local API
4. **Fine-tune models** - Train on your own data (offline)
5. **Share setup** - Help others go offline too!

---

## Resources

- **Model Hub:** https://huggingface.co/models?other=gguf
- **llama.cpp:** https://github.com/ggerganov/llama.cpp
- **Community:** https://github.com/ItsMehRAWRXD/cloud-hosting
- **GGUF Format:** https://github.com/ggerganov/ggml/blob/master/docs/gguf.md

---

## License

MIT - Use freely, contribute improvements!

**Enjoy your local AI freedom! 🎉**
