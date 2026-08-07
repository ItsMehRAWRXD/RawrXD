# Show HN: RawrXD – A Sovereign AI IDE That Runs 70B Models Locally

**TL;DR:** I built a native Windows IDE with AI code completion that runs entirely on your machine. No cloud, no telemetry, no subscription. It loads GGUF models (7B to 671B), does dual-GPU tensor parallelism, and hits 10-12 tokens/sec on a 70B model. [Download](https://github.com/ItsMehRAWRXD/RawrXD/releases) | [GitHub](https://github.com/ItsMehRAWRXD/RawrXD)

---

## The Problem

I work on code I can't send to the cloud. Defense contracts, financial algorithms, proprietary ML models. The existing options are:

1. **GitHub Copilot** – Sends your code to Microsoft
2. **Cursor** – Sends your code to OpenAI
3. **Local LLM servers** – Terminal-only, no IDE integration
4. **VS Code + extensions** – Still phones home, complex setup

I wanted something that:
- Loads any GGUF model I choose
- Runs entirely offline
- Feels like a modern IDE
- Handles 70B+ parameter models on consumer hardware

So I built it.

---

## What It Does

**RawrXD** is a native Win32 IDE with:

### AI Features
- **Inline ghost text** – Suggestions appear as you type (Tab to accept, Esc to dismiss)
- **Interruptible generation** – Hit Escape, it stops immediately
- **Multi-GPU support** – Automatically splits layers across GPUs by VRAM ratio
- **Any GGUF model** – From TinyLlama (1.1B) to DeepSeek-v3.1 (671B)

### Editor Features
- **Scintilla-based** – Syntax highlighting, folding, multi-cursor
- **LSP integration** – Diagnostics, hover tooltips, autocomplete, go-to-definition
- **Debugger** – Breakpoints, call stack, memory view
- **Git UI** – Diff viewer, blame annotations, commit dialog

### Performance
| Model | Size | Hardware | Speed |
|-------|------|----------|-------|
| Llama 3.2 3B | 2GB | RX 7800 XT | 50 tok/s |
| Mistral 7B | 4.5GB | Dual GPU | 25 tok/s |
| BigDaddyG 69B | 34.5GB | R9700 + 7800 XT | **10-12 tok/s** |
| DeepSeek 671B | 350GB | Unified memory | 0.5-2 tok/s |

*Yes, it actually runs a 671B model. Slowly, but it runs.*

---

## Technical Highlights

### The Hard Parts That Work

**1. Hardened GGUF Parser**
- 64-bit offsets throughout (handles 100GB+ models)
- Alignment validation (prevents the "4 page fault" bug)
- Bounds checking on every tensor access
- ~45 second load time for 69B model

**2. Dual-GPU Tensor Parallelism**
- Runtime detection via HIP
- Automatic layer splitting by VRAM ratio
- Minimal inter-GPU sync (each GPU processes its slice)
- Tested on Radeon AI PRO R9700 (32GB) + RX 7800 XT (16GB)

**3. Interruptible Generation**
- Global atomic flag checked every token
- 200ms max latency from keypress to stop
- Clean state reset, no memory leaks

**4. Ghost Text Engine**
- Thread-safe buffer with accept/dismiss
- Caret-aware positioning
- No flicker, no lag

**5. Security Sandbox**
- Tool execution limited to project directories
- Command blacklist (format, del /, rmdir /s)
- Automatic backups before file writes
- No shell injection vectors

---

## Architecture

```
RawrXD.exe (Win32)
├── Scintilla Editor (syntax, folding, LSP markers)
├── Ghost Text Overlay (inline AI completions)
├── LSP Client (clangd, pylsp, etc.)
├── ANSI Terminal (colored build output)
├── Git UI (diff, blame, log)
├── Agentic Supervisor (task queue, health monitoring)
└── Inference Engine
    ├── GGUF Loader (hardened 64-bit parser)
    ├── Multi-GPU Manager (HIP runtime)
    ├── Deep2 Engine (Vulkan compute)
    └── KV Cache + Sampler
```

**Lines of code:** ~25,000 (C++, MASM, HLSL)
**Dependencies:** Vulkan, Scintilla, Windows SDK
**External services:** None

---

## Installation

Download the installer: [RawrXD-v1.0.0-setup.exe](https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v1.0.0/RawrXD-v1.0.0-setup.exe)

Or build from source:
```powershell
git clone https://github.com/ItsMehRAWRXD/RawrXD
cd RawrXD
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja
```

---

## Use Cases

**Defense/Intelligence**
- Air-gapped networks
- Classified development
- No data exfiltration risk

**Finance/Trading**
- Proprietary algorithms
- Compliance requirements
- Latency-sensitive (no cloud round-trip)

**Healthcare**
- PHI protection
- HIPAA compliance
- Local model control

**Personal Projects**
- No subscription fees
- No usage limits
- Model ownership

---

## Pricing

**Solo:** $99/year (personal use, all features)
**Team:** $499/year (5 seats, priority support)
**Enterprise Source:** $25,000 (one-time, full source code, unlimited seats)

The GitHub release is fully functional. Pay if you want support or source access.

---

## What's Next

- [ ] Remote development over SSH
- [ ] Plugin marketplace
- [ ] macOS/Linux ports
- [ ] In-IDE LoRA fine-tuning

---

## Questions?

**Q: Why Windows only?**
A: Started as a Win32 learning project. Linux port is planned for v1.2.

**Q: Can it use NVIDIA GPUs?**
A: Currently AMD ROCm only. CUDA backend is ~2 weeks of work (volunteers welcome).

**Q: How does it compare to Ollama + VS Code?**
A: Ollama is terminal-only. RawrXD is a complete IDE with ghost text, LSP, debugger, and Git integration.

**Q: Is the AI any good?**
A: Depends on your model. With Llama 3.1 70B, it's competitive with GPT-4. With TinyLlama, it's a smart autocomplete.

**Q: Why "RawrXD"?**
A: Dinosaur noises + XD face. Also, available domain names.

---

## Demo Video

[90-second demo on YouTube](https://youtube.com/watch?v=rawrxd-demo)

Shows: Launch → Load 69B model → Type code → Ghost text appears → Accept completion → Build → ANSI colors in terminal

---

**Try it. Break it. Tell me what sucks.**

[GitHub](https://github.com/ItsMehRAWRXD/RawrXD) | [Issues](https://github.com/ItsMehRAWRXD/RawrXD/issues) | [Discord](https://discord.gg/rawrxd)

---

*Built by a solo developer over 90 days. 25,000 lines of C++. Zero external AI services.*
