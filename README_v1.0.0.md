# RawrXD Sovereign AI IDE v1.0.0

**A native Win32 AI development environment with zero cloud dependency.**

[![Release](https://img.shields.io/badge/release-v1.0.0-blue)](https://github.com/ItsMehRAWRXD/RawrXD/releases/tag/v1.0.0)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)](https://github.com/ItsMehRAWRXD/RawrXD)
[![License](https://img.shields.io/badge/license-Proprietary-red)](LICENSE)

---

## 🎯 What is RawrXD?

RawrXD is a **production-ready, native Windows IDE** that brings AI-powered development to your local machine. No cloud services. No data leakage. No subscription fees.

### Key Differentiators

| Feature | RawrXD | VS Code + Copilot | Cursor |
|---------|--------|-------------------|--------|
| **Offline Operation** | ✅ Fully local | ❌ Cloud required | ❌ Cloud required |
| **Data Privacy** | ✅ Zero external calls | ❌ Code sent to OpenAI | ❌ Code sent to OpenAI |
| **Model Ownership** | ✅ You own the weights | ❌ Rented access | ❌ Rented access |
| **Air-Gap Support** | ✅ Works isolated | ❌ Internet required | ❌ Internet required |
| **Native Performance** | ✅ Win32, no Electron | ❌ Electron-based | ❌ Electron-based |
| **Large Model Support** | ✅ 69B+ models locally | ❌ Limited by API | ❌ Limited by API |

---

## 🚀 Quick Start

### Download

Download the latest release: [RawrXD-v1.0.0-setup.exe](https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v1.0.0/RawrXD-v1.0.0-setup.exe)

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Windows 10 64-bit | Windows 11 64-bit |
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 16 GB | 64 GB |
| **GPU** | Any DirectX 12 | AMD Radeon 32GB VRAM |
| **Storage** | 10 GB | 100 GB (for models) |

### Installation

```powershell
# Download and run installer
RawrXD-v1.0.0-setup.exe

# Or build from source
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja
```

### First Run

1. Launch RawrXD from Start Menu
2. On first run, you'll be prompted to configure:
   - **Model Path**: Where your GGUF models are stored
   - **Workspace**: Your default project directory
   - **Theme**: Dark or light
3. Download a model (TinyLlama 1.1B is recommended for first test)
4. Open a file and start coding!

---

## ✨ Features

### 🤖 AI-Powered Coding

#### Ghost Text Completions
- **Inline suggestions** as you type
- **300ms average latency** (see benchmarks below)
- **Tab to accept**, Escape to dismiss
- Works with any GGUF model (7B to 69B+)

```cpp
// Type this:
int calculateSum(

// Ghost text appears:
int calculateSum(int a, int b) {
    return a + b;
}
```

#### AI Commands
- **Ctrl+Space**: Request completion
- **Ctrl+Shift+E**: Explain selected code
- **Ctrl+Shift+F**: Fix selected code
- **Escape**: Stop generation

### 🔧 Developer Tools

#### Scintilla Editor
- Syntax highlighting for 50+ languages
- Code folding and outlining
- Multi-cursor editing
- Find and replace with regex
- Line numbers and margin markers

#### LSP Integration
- Real-time diagnostics (red squiggles)
- Hover tooltips with documentation
- Autocomplete with signature help
- Go-to-definition
- Works with clangd, pylsp, and more

#### Integrated Terminal
- Full ANSI color support
- PowerShell and CMD support
- Build output with clickable errors
- Scrollback buffer

#### Git Integration
- Side-by-side diff viewer
- Blame annotations
- Commit dialog with staging
- Branch switching
- Push/pull with remote management

#### Debugger
- Breakpoint management
- Step over/into/out
- Call stack visualization
- Local variables and watches
- Memory and register views

### 🛡️ Security

#### Sandboxed Execution
- **Path validation**: Tools can only access allowed directories
- **Command blacklist**: Dangerous commands blocked
- **Backup creation**: Files backed up before modification
- **Undo support**: Rollback any tool operation

#### Privacy-First Design
- Zero network calls for AI features
- No telemetry or analytics
- No cloud model APIs
- All data stays on your machine

---

## 📊 Performance

### Benchmarks

All tests run on:
- **CPU**: AMD Ryzen 7 7800X3D
- **GPU**: AMD Radeon AI PRO R9700 (32GB) + RX 7800 XT (16GB)
- **RAM**: 64GB DDR5
- **Storage**: NVMe SSD

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| **Model Load (69B)** | <60s | 45s | ✅ PASS |
| **Ghost Text Latency** | <500ms | 300ms | ✅ PASS |
| **Token Generation (69B)** | >8 TPS | 10-12 TPS | ✅ PASS |
| **Memory Growth** | <1GB/hour | 200MB/hour | ✅ PASS |
| **IDE Startup** | <5s | 2.1s | ✅ PASS |

### Model Support

| Model | Size | Quant | VRAM | TPS |
|-------|------|-------|------|-----|
| TinyLlama 1.1B | 0.6 GB | Q4_K_M | 2 GB | 60+ |
| Llama 3.2 3B | 2.0 GB | Q4_K_M | 4 GB | 50+ |
| Mistral 7B | 4.5 GB | Q4_K_M | 6 GB | 25-30 |
| BigDaddyG-God 69B | 34.5 GB | Q4_0 | 40 GB | 10-12 |
| DeepSeek-v3.1 671B | 380 GB | Q4_K_M | 400 GB* | 0.5-2 |

*Requires unified memory with SSD paging

---

## 🏗️ Architecture

```
RawrXD IDE v1.0.0
│
├── Editor Layer
│   ├── Scintilla Editor (syntax, folding, multi-cursor)
│   ├── Ghost Text Engine (inline AI completions)
│   └── LSP UI Renderer (diagnostics, hover, autocomplete)
│
├── AI Runtime
│   ├── GGUF Loader (hardened parser, alignment fixes)
│   ├── Deep2 Engine (Vulkan compute, tensor parallelism)
│   ├── KV Cache Manager
│   └── Sampler (temperature, top-p, top-k)
│
├── Agentic Layer
│   ├── AgenticSupervisor (task orchestration)
│   ├── ToolExecutor (JSON-RPC, caching, undo)
│   └── FileTools (read, write, search, execute)
│
├── Developer Tools
│   ├── DebuggerCore (breakpoints, stepping, call stack)
│   ├── GitIntegration (diff, blame, commit)
│   └── ANSITerminalRenderer (colors, cursor, scrollback)
│
└── Platform
    ├── Win32 Window Management
    ├── Settings Persistence (INI-based)
    └── Security Sandbox
```

---

## 🛠️ Building from Source

### Prerequisites

- Windows 10/11 SDK
- Visual Studio 2022 or MinGW-w64
- CMake 3.20+
- Ninja (optional but recommended)
- Vulkan SDK (for GPU acceleration)

### Build Steps

```powershell
# Clone repository
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD

# Configure with CMake
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release

# Build
ninja

# Run tests
ctest --output-on-failure

# Package
ninja package
```

### Build Options

| Option | Description | Default |
|--------|-------------|---------|
| `RAWRXD_ENABLE_VULKAN` | Enable Vulkan GPU acceleration | ON |
| `RAWRXD_ENABLE_LSP` | Enable LSP client | ON |
| `RAWRXD_ENABLE_DEBUGGER` | Enable debugger | ON |
| `RAWRXD_BUILD_TESTS` | Build test suite | ON |

---

## 📖 Documentation

- [User Manual](docs/USER_MANUAL.md)
- [API Reference](docs/API_REFERENCE.md)
- [Security Whitepaper](docs/SECURITY_WHITEPAPER.md)
- [Performance Report](docs/PERFORMANCE_REPORT.md)
- [Architecture Overview](docs/ARCHITECTURE.md)

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```powershell
# Fork and clone
git clone https://github.com/YOUR_USERNAME/RawrXD.git
cd RawrXD

# Create branch
git checkout -b feature/my-feature

# Make changes, commit, push
git add .
git commit -m "Add feature"
git push origin feature/my-feature

# Open Pull Request
```

---

## 📜 License

RawrXD is proprietary software. See [LICENSE](LICENSE) for details.

### Commercial Licensing

- **Solo Developer**: $99/year
- **Team (5 seats)**: $499/year
- **Enterprise (source license)**: $25,000 one-time

Contact: licensing@rawrxd.dev

---

## 🙏 Acknowledgments

- **llama.cpp** - GGUF format and quantization techniques
- **Scintilla** - High-performance text editing component
- **clangd** - C++ language server
- **Vulkan** - GPU compute API

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/ItsMehRAWRXD/RawrXD/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ItsMehRAWRXD/RawrXD/discussions)
- **Email**: support@rawrxd.dev
- **Discord**: [Join Server](https://discord.gg/rawrxd)

---

## 🗺️ Roadmap

### v1.1.0 (Q4 2026)
- Plugin system
- Remote development (SSH)
- Additional model formats (GPTQ, AWQ)

### v1.2.0 (Q1 2027)
- Collaborative editing
- AI fine-tuning (LoRA)
- macOS and Linux ports

### v2.0.0 (2027)
- Multi-user server mode
- Web-based remote access
- Enterprise SSO integration

---

**Made with ❤️ by the RawrXD Team**

*Sovereign computing for sovereign developers.*
