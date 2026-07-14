# RawrXD Quick Start Guide

## Immediate Usage

### 1. Load a Model
```cmd
cd d:\rawrxd\compilers\native_toolchain
unified_model_streamer.exe load ..\..\bench_min.gguf
```

### 2. Test Streaming (requires Ollama running)
```cmd
unified_model_streamer.exe stream deepseek-r1:8b
```

### 3. Launch IDE
```cmd
cd d:\rawrxd\build_win32ide\bin
RawrXD-Win32IDE.exe
```

### 4. Run Model Manager
```cmd
cd d:\rawrxd\compilers\native_toolchain
model_manager.exe
```

## Build Everything
```cmd
cd d:\rawrxd
FINAL_BUILD_MASTER.bat
```

## System Components

| Component | Location | Purpose |
|-----------|----------|---------|
| Model Loader | `compilers\native_toolchain\unified_model_streamer.exe` | GGUF loading + streaming |
| IDE | `build_win32ide\bin\RawrXD-Win32IDE.exe` | Native Win32 IDE |
| Kernels | `src\asm\SwarmV29_*.obj` | PQC acceleration |
| Config | `config\agentic_config.json` | System settings |

## Status: ✅ OPERATIONAL
