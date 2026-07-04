# RawrXD Codex Module

## Overview

Unified CLI/GUI entry point for RawrXD with zero-dependency WinHTTP backend.

## Features

- **Auto-Detection**: Automatically detects console vs GUI mode
- **Zero Dependencies**: Pure Win32 API, no external libraries
- **HTTP Backend**: Native WinHTTP for API communication
- **JSON Parsing**: Built-in minimal JSON parser (JsonLite)
- **Unified Interface**: Single executable handles both CLI and GUI modes

## Files

| File | Purpose |
|------|---------|
| `main.cpp` | Unified entry point with auto-detection |
| `CodexCLI.hpp/cpp` | CLI interface for GPT/Codex API |
| `CodexGUI.hpp/cpp` | Win32 GUI interface |
| `HttpClient.hpp/cpp` | WinHTTP client implementation |
| `JsonLite.hpp` | Minimal JSON parser (zero-dependency) |
| `CMakeLists.txt` | CMake build configuration |
| `build.bat` | Windows batch build script |

## Build Instructions

### Using CMake
```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

### Using Batch Script
```bash
cd src\codex
build.bat
```

### Manual MinGW Build
```bash
g++ -std=c++17 -O3 -Wall -Wextra -mwindows -municode -I. -I..\..\include \
    main.cpp CodexCLI.cpp CodexGUI.cpp HttpClient.cpp \
    -o build\rawrxd-codex.exe \
    -lwinhttp -luser32 -lgdi32 -lshell32 -lcomctl32 \
    -static-libgcc -static-libstdc++
```

## Usage

### GUI Mode (no arguments)
```bash
rawrxd-codex.exe
```

### CLI Mode
```bash
# Show version
rawrxd-codex.exe version

# Complete prompt
rawrxd-codex.exe complete "Your prompt here"

# Interactive REPL
rawrxd-codex.exe repl
```

## Architecture

```
main.cpp
    ├── No args ──> GUI Mode (CodexGUI)
    └── Args ─────> CLI Mode (CodexCLI)
                          └── HttpClient (WinHTTP)
```

## Dependencies

- Windows SDK (WinHTTP, Win32 API)
- C++17 compiler (MSVC or MinGW)

## Status

✅ Unified entry point complete
✅ HTTP backend (WinHTTP) implemented
✅ JSON parser (JsonLite) integrated
✅ Build system configured
⏳ Ready for integration testing
