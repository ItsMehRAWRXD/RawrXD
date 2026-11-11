# RawrXD Architecture Diagrams

## Data Flow: AI-Assisted Coding Session

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   User Types    │────▶│   MonacoCore    │────▶│  Context Gather │
│   Code in IDE   │     │  (Gap Buffer)   │     │  (256 tokens)   │
└─────────────────┘     └────────┬────────┘     └────────┬────────┘
                                 │                       │
                                 │                       ▼
                                 │              ┌─────────────────┐
                                 │              │  Tokenizer      │
                                 │              │  (BPE/FNV-1a)   │
                                 │              └────────┬────────┘
                                 │                       │
                                 ▼                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                      Sovereign Inference Engine                   │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │   INT8      │    │   BF16      │    │   KV Cache          │  │
│  │   Path      │ or │   Path      │───▶│   (VirtualAlloc)    │  │
│  │  (fast)     │    │ (accurate)  │    │   256MB per session │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                         Output Stream                            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │   Token 1   │───▶│   Token 2 │───▶│   Token N         │  │
│  │   "def"     │    │   " fib"    │    │   ":"             │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                      Ghost Text Display                          │
│                    (RichEdit Control)                            │
└──────────────────────────────────────────────────────────────────┘
```

## Memory Layout

```
RawrXD Process Memory (x64)
┌─────────────────────────────────────────────────────────────────┐
│ 0x00000000'00000000                                              │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Code Segment (.text)                                     │    │
│  │ • IDE Core (C++): ~5MB                                  │    │
│  │ • MASM Kernels: ~2MB                                    │    │
│  │ • Sovereign Engine: ~8MB                                │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Data/BSS (.data/.bss)                                    │    │
│  │ • Static variables: ~1MB                                  │    │
│  │ • Theme data: ~500KB                                      │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Heap (malloc/VirtualAlloc)                              │    │
│  │ • Gap Buffer: ~1MB per open file                        │    │
│  │ • LSP buffers: ~10MB                                    │    │
│  │ • UI elements: ~5MB                                     │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Shared Arena (VirtualAlloc, 64-byte aligned)             │    │
│  │ • 8 sessions × 32MB = 256MB total                       │    │
│  │ • INT8 quantized weights                                │    │
│  │ • Head-major planar KV cache                            │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Model Weights (MMAP, read-only)                          │    │
│  │ • GGUF file mapping: 1-4GB                               │    │
│  │ • Zero-copy, shared across sessions                     │    │
│  │ • Q4_K quantized (4.5 bits/weight)                      │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│ 0x00007FFF'FFFFFFFF                                            │
└─────────────────────────────────────────────────────────────────┘
```

## Threading Model

```
RawrXD Thread Architecture
┌─────────────────────────────────────────────────────────────────┐
│ Main Thread (UI)                                                │
│ ├── Message Pump (GetMessage/DispatchMessage)                   │
│ ├── RichEdit Rendering                                          │
│ ├── Command Palette                                             │
│ └── Status Bar Updates                                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Worker Thread Pool (4 threads)                                  │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ LSP Handler │  │ AI Worker   │  │ File I/O    │             │
│  │ Thread      │  │ Thread      │  │ Thread      │             │
│  │             │  │             │  │             │             │
│  │ • Parse     │  │ • Tokenize  │  │ • Async     │             │
│  │ • Send RPC  │  │ • Inference │  │   load      │             │
│  │ • Process   │  │ • Stream    │  │ • Auto-save │             │
│  │   response  │  │   output    │  │ • Indexing  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                 │
│  ┌─────────────┐                                               │
│  │ Background  │                                               │
│  │ Tasks       │                                               │
│  │             │                                               │
│  │ • Syntax    │                                               │
│  │   highlight │                                               │
│  │ • Telemetry │                                               │
│  │ • Diagnostics│                                              │
│  └─────────────┘                                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ GPU Thread (Optional)                                           │
│ ├── Vulkan Command Buffer Submission                            │
│ ├── Async Memory Transfers                                    │
│ └── Compute Shader Dispatch                                     │
└─────────────────────────────────────────────────────────────────┘
```

## Security Layers

```
RawrXD Security Architecture
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Input Validation                                       │
│ ├── GGUF Validator                                              │
│ │   ├── Magic bytes (0x46554747)                               │
│ │   ├── Version check (3)                                      │
│ │   ├── Tensor bounds (<10000)                                 │
│ │   └── Metadata sanity                                        │
│ │                                                              │
│ ├── PE Validator                                               │
│ │   ├── DOS header (MZ)                                        │
│ │   ├── NT header (PE)                                         │
│ │   ├── Section alignment                                      │
│ │   └── Relocation integrity                                   │
│ │                                                              │
│ └── JSON-RPC Validator                                         │
│     ├── Message size limits                                    │
│     ├── Schema validation                                       │
│     └── Timeout enforcement                                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 2: Memory Protection                                      │
│ ├── ASLR (Address Space Layout Randomization)                   │
│ ├── DEP (Data Execution Prevention)                           │
│ ├── Stack canaries                                              │
│ └── Heap integrity checks                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 3: Sandboxing                                             │
│ ├── LSP process isolation                                       │
│ ├── AI inference limits (token caps)                          │
│ └── File system access controls                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Build Pipeline

```
Genesis Build System Flow
┌─────────────────────────────────────────────────────────────────┐
│ Source Files                                                    │
│ ├── C++: src/win32app/*.cpp                                    │
│ └── MASM: src/asm/*.asm                                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Stage 1: Environment Discovery (PowerShell)                     │
│ ├── Find VS2022 installation                                   │
│ ├── Locate ml64.exe, cl.exe, link.exe                          │
│ └── Set GENESIS_* environment variables                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Stage 2: C++ Compilation (cl.exe)                               │
│ ├── main.cpp → main.obj                                        │
│ ├── lsp_client.cpp → lsp_client.obj                            │
│ ├── ui_manager.cpp → ui_manager.obj                              │
│ └── editor_core.cpp → editor_core.obj                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Stage 3: MASM Assembly (ml64.exe)                               │
│ ├── inference_core.asm → inference_core.obj                    │
│ ├── kv_cache_mgr.asm → kv_cache_mgr.obj                        │
│ ├── RawrXD_Tokenizer.asm → RawrXD_Tokenizer.obj                │
│ └── RawrXD_AgenticOrchestrator.asm → ...                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Stage 4: Unified Link (link.exe)                                │
│ ├── Combine all .obj files                                    │
│ ├── Link kernel32.lib, user32.lib, etc.                        │
│ └── Emit RawrXD-Win32IDE.exe                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Output: RawrXD-Win32IDE.exe (~35MB)                            │
└─────────────────────────────────────────────────────────────────┘
```

## Performance Metrics

```
RawrXD Performance Characteristics

Startup Sequence
├─ Load executable:        ~50ms
├─ Initialize RichEdit:    ~30ms
├─ Load themes:            ~20ms
├─ Connect LSP:            ~100ms
└─ Total startup:          ~200ms

Editor Operations
├─ File open (10k lines):  Instant
├─ Key press latency:      <1ms
├─ Syntax highlight:       <16ms
└─ Auto-complete:          <50ms

AI Inference (Sovereign Engine)
├─ First token (TTFT):     106ms
├─ Token generation:       22ms/token
├─ Throughput:             47 TPS
└─ Memory per session:   256MB

Memory Footprint
├─ Base IDE:             45MB
├─ Loaded project:       +50MB
├─ LSP buffers:          +20MB
├─ AI inference:         +256MB
└─ Total (typical):      ~400MB

Comparison: RawrXD vs VS Code
├─ Startup:              200ms vs 2-5s      (10-25× faster)
├─ Memory (idle):        45MB vs 300MB      (6.7× less)
├─ Memory (loaded):      150MB vs 1-2GB     (6.7-13× less)
└─ File open (10k):      Instant vs ~2s     (N/A)
```

---

**Document:** RawrXD Architecture Diagrams  
**Version:** 1.0.0  
**Date:** 2026-06-30
