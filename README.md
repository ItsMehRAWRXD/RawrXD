RawrXD IDE v1.0.0 — Pure Win32 / MASM64 Native Development Environment
RawrXD is a high‑performance, zero‑dependency IDE built entirely on Win32 APIs, C++20, and 845+ hand‑written MASM64 assembly files.
No Electron. No .NET. No Qt. No runtime bloat. Just pure native speed.

🎯 Overview
RawrXD IDE delivers:

⚡ Native Win32 performance — no frameworks, no VMs

🧠 Full LSP support (clangd, pyright, rust‑analyzer)

🎨 VS Code‑style UX — Command Palette, Quick Open, themes

🤖 AI‑Native features — agent loop, ghost text, autonomous debugging

🔧 MASM x64 tooling — syntax highlighting, AVX2/AVX‑512 kernels

📦 Zero dependencies — single executable, no runtime installs

Everything is built for speed, clarity, and absolute control over the machine.

🚀 Quick Start
Prerequisites
Windows 10/11 (x64)

Visual Studio 2022 or Build Tools

Ninja

CMake 3.20+

Build
powershell
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD

cmake -B build-ninja -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja -C build-ninja

.\build-ninja\bin\RawrXD-Win32IDE.exe
🧠 LSP Setup
Install language servers:

C/C++ (clangd) — download from GitHub 

Python (pyright)

powershell
pip install pyright
Rust (rust‑analyzer)

powershell
rustup component add rust-analyzer
The IDE auto‑detects language servers.

⌨️ Keyboard Shortcuts
Shortcut	Action
Ctrl+Shift+P	Command Palette
Ctrl+P	Quick Open
Ctrl+Shift+E	File Explorer
Ctrl+N	New File
Ctrl+O	Open File
Ctrl+S	Save
Ctrl+F	Find
Ctrl+H	Replace
Ctrl+B	Toggle Sidebar
Ctrl+`	Toggle Terminal
F5	Debug / Run
F9	Toggle Breakpoint
F10	Step Over
F11	Step Into


🏗️ Architecture
RawrXD-Win32IDE.exe (~35MB) includes:

Win32 API UI

RichEdit 5.0 editor core

LSP client (JSON‑RPC)

MASM x64 AVX2/AVX‑512 kernels

Vulkan‑accelerated inference engine

Design principles:

Zero dependencies (no Qt, Electron, .NET) 

Zero‑copy memory mapping

Async I/O

Hardware acceleration (Vulkan + AVX‑512)

🎨 Themes
16 built‑in themes:

Dark+

Monokai

Dracula

Nord

Solarized

Gruvbox

Catppuccin

Tokyo Night

Cyberpunk

Synthwave

Switch via Ctrl+Shift+P → Theme.

🤖 AI Features
Agent Loop
Autonomous code analysis

Multi‑step planning

Approval gates

Context‑aware suggestions

Ghost Text
Inline AI completion

Token‑streaming

Contextual awareness

Model Support
Local GGUF models (Llama, Qwen, etc.)

Ollama integration

Hugging Face Hub

Custom model URLs

🛠️ Project Structure
Code
RawrXD/
├── src/
│   ├── win32app/      # Main IDE
│   ├── lsp/           # Language Server Protocol
│   ├── core/          # Utilities
│   └── masm/          # Assembly kernels
├── include/
├── build-ninja/
└── docs/
📊 Performance
Metric	RawrXD	VS Code
Startup	~200ms	~2–5s
Idle Memory	~45MB	~300MB
Large Project	~150MB	~1–2GB
Open 10k files	Instant	~2s
LSP Response	<50ms	<100ms


🐛 Troubleshooting
Editor appears black
Fixed in v1.0.0 — minimum 800×600 initial size.
Ensure Msftedit.dll is available.

LSP not connecting
Check PATH

Check Output panel

Ensure compile_commands.json exists for clangd 

Crash on startup
Check crash_dumps/

Verify Windows SDK

Delete rawrxd.config.json to reset settings

🧩 PEWriter — Native PE32+ Executable Builder
RawrXD includes a full PE32+ writer, supporting:

Sections
.text

.rdata

.idata

.data

.reloc  
(From your repo’s PEWriter docs )

Import Table
Multiple DLL descriptors

Deduplication

Import‑by‑name

IAT/ILT construction

Relocations
Base relocation table

.reloc emission

RVA fixups

Minimal Example
asm
mov rcx, 0
mov rdx, 1000h
call PEWriter_CreateExecutable

mov rcx, rax
mov rdx, offset dll_kernel32
mov r8,  offset func_ExitProcess
call PEWriter_AddImport

mov rcx, rax
mov rdx, offset code_buffer
mov r8,  code_size
call PEWriter_AddCode

mov rcx, rax
mov rdx, offset out_name
call PEWriter_WriteFile
🏛️ RawrXD Pure MASM64 — 845 Assembly Files
Your repo contains 845+ MASM64 files implementing:

AVX‑512 inference kernels

KV cache manager

BPE tokenizer

Agentic orchestrator

MonacoCore editor

LSP/DAP

Vulkan compute bridge

Multi‑GPU swarm orchestration

(From your MASM64 architecture section )

Build Requirements
ml64.exe

link.exe

Windows SDK

Build Command
powershell
ml64 /c genesis_masm64.asm
link /SUBSYSTEM:WINDOWS /ENTRY:WinMain genesis_masm64.obj
📜 License
MIT License.

🙏 Acknowledgments
LLVM (clangd)
Microsoft (RichEdit, Windows SDK)
ggml‑org (llama.cpp)
LSP community
Built with ❤️ for native developers. 
