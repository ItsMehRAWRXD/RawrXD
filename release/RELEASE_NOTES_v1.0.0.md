# RawrXD v1.0.0 Release Notes
**Sovereign AI IDE - Production Release**

**Date:** 2026-07-29  
**Status:** Production Ready  
**Download:** [RawrXD-v1.0.0-setup.exe](https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v1.0.0/RawrXD-v1.0.0-setup.exe)

---

## 🎯 What is RawrXD?

RawrXD is a **native Windows IDE with local AI code completion** that runs entirely on your machine. No cloud. No telemetry. No subscription.

- **Load any GGUF model** (7B to 671B parameters)
- **Dual-GPU tensor parallelism** for massive models
- **Inline ghost text completions** as you type
- **Full LSP support** (diagnostics, hover, autocomplete)
- **Integrated terminal** with ANSI colors
- **Git integration** (diff, blame, log)
- **Agentic coding tools** (read, write, search, execute)

---

## ✨ Key Features

### Local AI Inference
- **GGUF model loader** with hardened 64-bit parser
- **Multi-GPU support** (AMD Radeon AI PRO R9700 + RX 7800 XT tested)
- **Automatic tensor splitting** based on VRAM ratios
- **Interruptible generation** (ESC to stop anytime)
- **Performance:** 10-12 TPS on 69B Q4_0 models

### Editor Experience
- **Scintilla-based editor** with syntax highlighting
- **Ghost text completions** inline as you type
- **LSP integration** for C++, Python, and more
- **Multi-cursor editing** and code folding
- **VS Code-compatible keybindings**

### Development Tools
- **Integrated terminal** with full ANSI support
- **Git UI** with diff viewer and blame annotations
- **Debugger** with breakpoints and call stack
- **Agentic tools** for automated code operations
- **Build system integration**

### Security & Privacy
- **100% local execution** - no network calls for AI
- **Sandboxed tool execution** with path validation
- **No telemetry** - your code never leaves your machine
- **Enterprise-ready** with source licensing available

---

## 📊 Performance Benchmarks

| Model | Size | Quantization | GPUs | Tokens/Second |
|-------|------|--------------|------|---------------|
| TinyLlama 1.1B | 0.6 GB | Q4_K_M | Single | 50-60 |
| Llama 3.2 3B | 2.0 GB | Q4_K_M | Single | 50-60 |
| Mistral 7B | 4.5 GB | Q4_K_M | Dual | 25-30 |
| BigDaddyG-God 69B | 34.5 GB | Q4_0 | Dual | **10-12** |
| DeepSeek-v3.1 671B | 350 GB | Q4_K_M | Unified Memory | 0.5-2 |

*Tested on AMD Radeon AI PRO R9700 (32GB) + RX 7800 XT (16GB)*

---

## 🚀 Quick Start

### Installation
1. Download `RawrXD-v1.0.0-setup.exe`
2. Run installer (requires Windows 10 1809+ 64-bit)
3. Launch RawrXD from Start Menu

### First Run
1. On first launch, RawrXD will prompt for a model
2. Select the included TinyLlama 1.1B or download a larger model
3. Open a file and start typing to see ghost text completions
4. Press **Tab** to accept, **Escape** to dismiss

### Loading Larger Models
```powershell
# Set GPU visibility (exclude integrated GPU)
$env:HIP_VISIBLE_DEVICES="0,2"

# Launch with specific model
RawrXD.exe --model "C:\Models\bigdaddyg-god-fast.gguf" --tensor-split 2,1
```

---

## 🛠️ System Requirements

**Minimum:**
- Windows 10 version 1809 or later (64-bit)
- 8 GB RAM
- 2 GB free disk space
- Any DirectX 11 capable GPU

**Recommended:**
- Windows 11
- 32 GB RAM
- AMD GPU with ROCm support (Radeon 7000 series)
- 50 GB free disk space (for large models)

**For 70B+ Models:**
- 64 GB RAM
- Dual AMD GPUs with 48GB+ combined VRAM
- NVMe SSD for model storage

---

## 📁 File Associations

RawrXD registers file associations for:
- `.cpp`, `.h`, `.hpp` - C++ source files
- `.py` - Python source files
- `.rs` - Rust source files
- `.go` - Go source files

Double-click any supported file to open in RawrXD.

---

## 🎮 Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Space` | Trigger autocomplete |
| `Tab` | Accept ghost text completion |
| `Escape` | Dismiss ghost text / Cancel generation |
| `Ctrl+Shift+P` | Command palette |
| `Ctrl+P` | Quick file open |
| `Ctrl+Shift+F` | Search across files |
| `Ctrl+G` | Go to line |
| `F5` | Start debugging |
| `F9` | Toggle breakpoint |
| `F10` | Step over |
| `F11` | Step into |
| `Ctrl+Shift+B` | Build project |
| `Ctrl+`` | Toggle terminal |

---

## 🐛 Known Issues

1. **Large model loading** may take 30-60 seconds on HDD (use SSD)
2. **First completion** after model load may have higher latency
3. **Vulkan validation layers** may impact performance (disable in release builds)
4. **Git operations** on repositories with 10k+ files may be slow

---

## 🔒 Security Notes

- All AI inference runs locally - no data sent to external servers
- Tool execution is sandboxed to project directories
- Dangerous commands (format, del /, rmdir /s) are blocked
- File writes create automatic backups

---

## 📈 Roadmap

### v1.1.0 (Q3 2026)
- Remote development over SSH
- Plugin marketplace
- Additional language servers
- Improved debugger with memory visualization

### v1.2.0 (Q4 2026)
- AI fine-tuning in IDE
- Collaborative editing
- Cloud sync (optional, encrypted)
- macOS and Linux ports

---

## 💼 Enterprise Licensing

**Solo License:** $99/year  
**Team License:** $499/year (5 seats)  
**Enterprise Source License:** $25,000 (one-time, includes full source code)

Contact: enterprise@rawrxd.dev

---

## 🙏 Acknowledgments

- **llama.cpp** - GGUF format and inference kernels
- **Scintilla** - Editor component
- **Vulkan** - GPU compute
- **ROCm** - AMD GPU support

---

## 📞 Support

- **Documentation:** https://docs.rawrxd.dev
- **GitHub Issues:** https://github.com/ItsMehRAWRXD/RawrXD/issues
- **Discord:** https://discord.gg/rawrxd
- **Email:** support@rawrxd.dev

---

**Built with ❤️ for developers who value privacy and performance.**

*© 2026 RawrXD Labs. All rights reserved.*
