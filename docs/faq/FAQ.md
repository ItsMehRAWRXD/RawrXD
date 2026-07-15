# Sovereign IDE — Frequently Asked Questions
## Common Questions and Answers

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** Complete

---

## Table of Contents

1. [General Questions](#1-general-questions)
2. [Installation](#2-installation)
3. [Features](#3-features)
4. [Extensions](#4-extensions)
5. [AI and ML](#5-ai-and-ml)
6. [Performance](#6-performance)
7. [Development](#7-development)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. General Questions

### Q: What is Sovereign IDE?

**A:** Sovereign IDE is a high-performance, AI-powered integrated development environment designed for reverse engineering, binary analysis, and advanced software development. It features:

- 256 SEG (Sovereign Execution Grid) nodes for distributed computing
- 128 MoE (Mixture of Experts) for AI model optimization
- 487 capabilities across 49 batches
- Pure x64 MASM core with C ABI and C++17 interfaces
- Zero external dependencies

### Q: Is Sovereign IDE free?

**A:** Sovereign IDE offers multiple tiers:

- **Community Edition:** Free, open-source
- **Professional Edition:** Paid, additional features
- **Enterprise Edition:** Custom pricing, full feature set

### Q: What platforms are supported?

**A:** Sovereign IDE supports:

- Windows 10/11 (x64)
- Linux (x64, ARM64)
- macOS 10.15+ (Intel, Apple Silicon)

### Q: How is Sovereign IDE different from other IDEs?

**A:** Key differentiators:

| Feature | Sovereign IDE | Other IDEs |
|---------|---------------|------------|
| Architecture | Pure MASM + C/C++ | Electron/Java-based |
| AI Integration | Native MoE system | External APIs |
| Binary Analysis | Built-in disassembly | Requires plugins |
| Performance | ~50MB memory | 300MB+ memory |
| Dependencies | Zero | Many |

---

## 2. Installation

### Q: How do I install Sovereign IDE?

**A:** Installation steps:

1. Download from [releases page](https://github.com/ItsMehRAWRXD/RawrXD/releases)
2. Run installer (Windows) or extract archive (Linux/macOS)
3. Follow setup wizard
4. Launch Sovereign IDE

### Q: Can I install Sovereign IDE without admin rights?

**A:** Yes, use the portable version:

```bash
# Download portable archive
# Extract to user directory
# Run sovereign.exe (Windows) or ./sovereign (Linux/macOS)
```

### Q: How do I update Sovereign IDE?

**A:** Update methods:

1. **Automatic:** Settings → Update → Check Automatically
2. **Manual:** Help → Check for Updates
3. **Command Line:** `sovereign --update`

### Q: Can I have multiple versions installed?

**A:** Yes:

```bash
# Install to different directories
C:\SovereignIDE-stable\
C:\SovereignIDE-insiders\

# Use different data directories
sovereign --user-data-dir ~/.sovereign-stable
sovereign --user-data-dir ~/.sovereign-insiders
```

---

## 3. Features

### Q: What programming languages are supported?

**A:** Sovereign IDE supports 50+ languages:

**Native Support:**
- C/C++
- Python
- JavaScript/TypeScript
- Rust
- Go
- Java
- C#

**Via Extensions:**
- Ruby
- PHP
- Swift
- Kotlin
- And 40+ more

### Q: Does Sovereign IDE support debugging?

**A:** Yes, comprehensive debugging support:

- Native code debugging (GDB, LLDB)
- Python debugging
- JavaScript/Node.js debugging
- Remote debugging
- Multi-threaded debugging
- Memory debugging

### Q: What version control systems are supported?

**A:** Built-in Git support with:

- Full Git workflow
- GitHub integration
- GitLab integration
- Bitbucket integration
- Azure DevOps
- SVN via extension

### Q: Can I customize the interface?

**A:** Extensive customization available:

```json
{
    "workbench.colorTheme": "Sovereign Dark",
    "workbench.iconTheme": "Sovereign Icons",
    "editor.fontSize": 14,
    "editor.fontFamily": "Fira Code",
    "editor.minimap.enabled": true
}
```

---

## 4. Extensions

### Q: Where can I find extensions?

**A:** Extensions available from:

1. **Built-in Marketplace:** Extensions view (`Ctrl+Shift+X`)
2. **GitHub:** [Sovereign Extensions](https://github.com/ItsMehRAWRXD/extensions)
3. **Third-party:** Compatible with Sovereign Extension API

### Q: Are VS Code extensions compatible?

**A:** Partially compatible:

- Extensions using standard APIs: Yes
- Extensions using VS Code-specific APIs: May require adaptation
- Check compatibility in extension details

### Q: How do I develop my own extension?

**A:** Extension development:

1. Install Node.js
2. Install Yeoman generator: `npm install -g yo generator-sovereign`
3. Generate extension: `yo sovereign`
4. Develop and test
5. Package: `vsce package`

See [Extension Development Guide](../training/Module11_Expert_ExtensionDevelopment.md)

### Q: Can extensions harm my system?

**A:** Extensions are sandboxed:

- Run in separate process
- Limited file system access
- Permission-based API access
- Review code before installing

---

## 5. AI and ML

### Q: What AI models are supported?

**A:** Supported formats:

- GGUF (llama.cpp)
- GGML
- SafeTensors
- ONNX
- PyTorch (via conversion)

### Q: Do I need a GPU for AI features?

**A:** GPU optional:

- **CPU:** Works on any modern CPU (slower)
- **GPU:** NVIDIA CUDA, AMD ROCm, Intel oneAPI (faster)
- **Quantized models:** Run well on CPU

### Q: How do I add my own AI model?

**A:** Steps:

1. Download or convert model to GGUF
2. Place in models directory
3. Configure in settings:
   ```json
   {
       "ai.model.path": "${workspaceFolder}/models/my-model.gguf",
       "ai.model.gpuLayers": 35
   }
   ```
4. Reload window

### Q: Is my code sent to external servers?

**A:** No, Sovereign IDE uses local AI:

- All processing on your machine
- No cloud API calls
- No code transmission
- Complete privacy

### Q: What is the MoE Governor?

**A:** MoE (Mixture of Experts) Governor:

- Manages AI model execution
- Optimizes for your hardware
- Prunes unnecessary experts
- Quantizes models automatically
- Enables running 800B+ models on consumer hardware

---

## 6. Performance

### Q: Why is Sovereign IDE using so much memory?

**A:** Common causes and solutions:

1. **Large Projects:** Exclude folders in settings
2. **Extensions:** Disable unused extensions
3. **AI Models:** Reduce context length
4. **Git Repositories:** Limit repository size

### Q: How can I improve startup time?

**A:** Optimization tips:

```json
{
    "workbench.startupEditor": "none",
    "extensions.autoUpdate": false,
    "editor.restoreViewState": false
}
```

### Q: Can I run Sovereign IDE on a low-end machine?

**A:** Minimum requirements:

- **RAM:** 4GB (8GB recommended)
- **CPU:** Dual-core processor
- **Disk:** 1GB free space
- **GPU:** Not required

Disable features:
```json
{
    "editor.minimap.enabled": false,
    "editor.renderWhitespace": "none",
    "ai.enabled": false
}
```

### Q: How do I profile performance?

**A:** Built-in profiler:

1. Help → Toggle Developer Tools
2. Performance tab
3. Record and analyze

---

## 7. Development

### Q: How do I build Sovereign IDE from source?

**A:** Build instructions:

```bash
# Clone repository
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD

# Install dependencies
npm install

# Build
npm run build

# Package
npm run package
```

See [Build System Documentation](../build/Build_System_Overview.md)

### Q: How do I contribute to Sovereign IDE?

**A:** Contribution process:

1. Fork repository
2. Create feature branch
3. Make changes
4. Run tests: `npm test`
5. Submit pull request

See [Contributing Guidelines](../contributing/CONTRIBUTING.md)

### Q: Where is the documentation?

**A:** Documentation locations:

- **Online:** [docs.sovereign.io](https://docs.sovereign.io)
- **GitHub:** `/docs` directory
- **Offline:** Help → Documentation
- **API:** [API Reference](../api/API_Reference_Index.md)

### Q: How do I report a bug?

**A:** Bug reporting:

1. Check [existing issues](https://github.com/ItsMehRAWRXD/RawrXD/issues)
2. Create new issue with:
   - IDE version
   - OS version
   - Steps to reproduce
   - Expected vs actual behavior
   - Logs and screenshots

---

## 8. Troubleshooting

### Q: Where are the log files?

**A:** Log locations:

```
Windows: %APPDATA%\SovereignIDE\logs\
Linux: ~/.config/SovereignIDE/logs/
macOS: ~/Library/Logs/SovereignIDE/
```

### Q: How do I reset settings?

**A:** Reset methods:

```bash
# Command Palette
Preferences: Open Settings (JSON)
# Delete all content, save

# Or delete file
rm ~/.config/SovereignIDE/settings.json
```

### Q: IDE is crashing, what should I do?

**A:** Troubleshooting steps:

1. Start in safe mode: `sovereign --disable-extensions`
2. Check logs for errors
3. Update to latest version
4. Report issue with logs

### Q: How do I get support?

**A:** Support channels:

1. **Documentation:** [docs.sovereign.io](https://docs.sovereign.io)
2. **GitHub Issues:** Bug reports
3. **GitHub Discussions:** Questions
4. **Discord:** [discord.gg/sovereign](https://discord.gg/sovereign)
5. **Stack Overflow:** Tag `sovereign-ide`

---

## Quick Reference

### Keyboard Shortcuts

| Action | Windows/Linux | macOS |
|--------|---------------|-------|
| Command Palette | `Ctrl+Shift+P` | `Cmd+Shift+P` |
| Quick Open | `Ctrl+P` | `Cmd+P` |
| Find in Files | `Ctrl+Shift+F` | `Cmd+Shift+F` |
| Go to Line | `Ctrl+G` | `Cmd+G` |
| Toggle Terminal | `` Ctrl+` `` | `` Cmd+` `` |

### Command Line Options

```bash
sovereign [options] [path]

Options:
  --version              Show version
  --help                 Show help
  --disable-extensions   Start without extensions
  --disable-gpu          Disable GPU acceleration
  --user-data-dir        Set data directory
  --extensions-dir       Set extensions directory
```

---

## Summary

This FAQ covers:

- ✅ General questions
- ✅ Installation
- ✅ Features
- ✅ Extensions
- ✅ AI and ML
- ✅ Performance
- ✅ Development
- ✅ Troubleshooting

**Status:** Complete

---

*End of FAQ*
