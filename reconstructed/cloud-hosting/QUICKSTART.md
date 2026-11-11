# 🚀 Quick Start - Local & Offline

**The Easiest Way to Run AI Models Locally!**

## One-Line Install & Run

```bash
# Download and run (Linux/macOS)
curl -sSL https://raw.githubusercontent.com/ItsMehRAWRXD/cloud-hosting/main/quick-start.sh | bash

# Or clone and run
git clone https://github.com/ItsMehRAWRXD/cloud-hosting.git
cd cloud-hosting
./quick-start.sh
```

That's it! Your AI is running at **http://localhost:8081** 🎉

---

## What Just Happened?

1. ✅ **Installed** llama.cpp and built native binaries
2. ✅ **Downloaded** a model (optional, can skip)
3. ✅ **Started** the API server on port 8080
4. ✅ **Launched** the Web UI on port 8081
5. ✅ **Opened** your browser automatically

## Features

- 🏠 **100% Local** - Everything runs on your machine
- 🔒 **100% Private** - Data never leaves your computer
- 📡 **Works Offline** - No internet needed after initial setup
- ⚡ **Fast** - Sub-10ms latency
- 💰 **Free** - No API costs, no limits
- 🎨 **Beautiful UI** - Simple and intuitive interface

## Available Scripts

| Script | Description |
|--------|-------------|
| `quick-start.sh` | **Start everything** (server + UI) |
| `install-local.sh` | Install RawrXD locally |
| `model-manager.sh` | Download/manage models |
| `start-ui.sh` | Start Web UI only |

## Manual Installation

If you prefer step-by-step:

### 1. Install

```bash
# Linux/macOS
./install-local.sh

# Windows
.\install-local.bat
```

### 2. Download Models

```bash
# List available models
./model-manager.sh list

# Download a model
./model-manager.sh download phi-2-q4
```

### 3. Start Server

```bash
# Start API server
rawrxd-serve

# Or start everything
./quick-start.sh
```

### 4. Use the UI

Open **http://localhost:8081** in your browser!

## System Requirements

### Minimum
- **OS:** Linux, macOS, or Windows
- **RAM:** 4GB (for small models)
- **Disk:** 5GB free space
- **CPU:** Any modern CPU

### Recommended
- **RAM:** 16GB+ (for larger models)
- **GPU:** NVIDIA (CUDA) or AMD (ROCm) for acceleration
- **Disk:** 20GB+ (for multiple models)

## Troubleshooting

### Server won't start

```bash
# Check if port 8080 is already in use
lsof -i :8080  # Linux/macOS
netstat -ano | findstr :8080  # Windows

# Use a different port
PORT=8081 rawrxd-serve
```

### No models found

```bash
# Download a model
./model-manager.sh download phi-2-q4

# Or manually download from HuggingFace
# Place .gguf files in ~/.local/share/rawrxd/models/
```

### Out of memory

```bash
# Use a smaller model
./model-manager.sh download tinyllama-q4  # Only 669MB

# Or close other applications
```

### Build failed

```bash
# Install dependencies first
# Ubuntu/Debian
sudo apt-get install build-essential cmake git

# macOS
brew install cmake git

# Then try again
./install-local.sh
```

## What's Next?

1. **Try different models** - `./model-manager.sh list`
2. **Integrate with tools** - Use the API at http://localhost:8080
3. **Build apps** - Create custom AI applications
4. **Share your setup** - Help others go offline!

## Compare: Cloud vs Local

| Feature | Cloud | Local |
|---------|-------|-------|
| Cost | $12-30/month | **FREE** |
| Privacy | Shared | **100% Private** |
| Internet | Required | **Optional** |
| Speed | 50-200ms | **<10ms** |
| Limits | API quotas | **None** |

## Documentation

- 📖 **Full Guide:** [OFFLINE_SETUP.md](OFFLINE_SETUP.md)
- 🔧 **Cloud Setup:** [README.md](README.md)
- 🦖 **MASM Implementation:** [masm64/README.md](masm64/README.md)

## Support

- **Issues:** https://github.com/ItsMehRAWRXD/cloud-hosting/issues
- **Models:** https://huggingface.co/models?other=gguf
- **Community:** https://github.com/ggerganov/llama.cpp

## License

MIT - Free to use, modify, and share!

---

**Enjoy your local AI freedom!** 🎉🦖
