# RawrXD Toolchain - User Manual
## Version 1.0 - No Shine Box Edition

---

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Command Line Interface](#command-line-interface)
5. [GUI IDE](#gui-ide)
6. [Language Compilers](#language-compilers)
7. [Project Files](#project-files)
8. [Troubleshooting](#troubleshooting)
9. [Advanced Topics](#advanced-topics)

---

## Introduction

RawrXD is a self-hosting development toolchain for Windows x64. It includes:

- **Native Assembler**: x64 assembly with 500+ instructions
- **Native Linker**: PE/COFF format support
- **C Compiler**: Working C to EXE compilation
- **Language Wrappers**: Python, JavaScript, Bash, PowerShell, C#, Java, EON
- **GUI IDE**: Native Win32 application with syntax highlighting

### System Requirements
- Windows 10/11 x64
- 4GB RAM minimum
- 100MB disk space

---

## Installation

### Method 1: Installer (Recommended)
1. Download `RawrXD-Toolchain-v1.0.exe`
2. Run installer
3. Follow prompts
4. Add to PATH: `C:\Program Files\RawrXD\bin`

### Method 2: Portable
1. Download `RawrXD-Toolchain-v1.0.zip`
2. Extract to desired location
3. Run `setup_portable.bat`

### Method 3: Build From Source
```batch
git clone https://github.com/ItsMehRAWRXD/rawrxd.git
cd rawrxd\compilers
bootstrap\bootstrap.bat
```

---

## Quick Start

### Hello World in Assembly
```asm
; hello.asm
_start:
    mov rax, 42
    ret
```

Compile:
```batch
rawrxd_ide_cli_v3.bat hello.asm
hello.exe
echo Exit code: %ERRORLEVEL%
```

Output:
```
Exit code: 42
```

### Hello World in C
```c
// hello.c
int main() {
    return 42;
}
```

Compile:
```batch
rawrxd_ide_cli_v3.bat hello.c
hello.exe
```

---

## Command Line Interface

### Basic Usage
```batch
rawrxd_ide_cli_v3.bat [command] [file]
```

### Commands
| Command | Description |
|---------|-------------|
| `test` | Run test suite |
| `list` | List available compilers |
| `help` | Show help |
| `[file]` | Compile file |

### Examples
```batch
; Compile assembly
rawrxd_ide_cli_v3.bat program.asm

; Compile C
rawrxd_ide_cli_v3.bat program.c

; Compile Python
rawrxd_ide_cli_v3.bat program.py

; Run tests
rawrxd_ide_cli_v3.bat test

; List compilers
rawrxd_ide_cli_v3.bat list
```

---

## GUI IDE

### Starting the IDE
```batch
RawrXD-IDE-v5.exe
```

### Interface
```
┌─────────────────────────────────────┐
│ [Open] [Save] [Compile] [Run]    │
├─────────────────────────────────────┤
│                                     │
│  Source Editor                      │
│  (with syntax highlighting)         │
│                                     │
├─────────────────────────────────────┤
│  Output Console                     │
│  Build results displayed here       │
├─────────────────────────────────────┤
│  Status: Ready                      │
└─────────────────────────────────────┘
```

### Features
- **File Picker**: Open files with GetOpenFileNameA
- **Syntax Highlighting**: Colors for comments, strings, keywords
- **Output Capture**: See compiler output in real-time
- **Error Parsing**: Automatic error detection
- **Project Files**: Save/load .rxproj files

---

## Language Compilers

### Supported Languages

| Language | Extension | Compiler | Runtime Required |
|----------|-----------|----------|------------------|
| Assembly | .asm | Native | None |
| C | .c | Native | None |
| C++ | .cpp | Native | None |
| Python | .py | Wrapper | Python |
| JavaScript | .js | Wrapper | Node.js |
| Bash | .sh | Wrapper | WSL/Git Bash |
| PowerShell | .ps1 | Wrapper | PowerShell |
| C# | .cs | Wrapper | .NET SDK |
| Java | .java | Wrapper | JDK |
| EON | .eon | Native | None |

### Native Compilers
Native compilers produce standalone executables with no dependencies.

### Wrapper Compilers
Wrapper compilers embed scripts in C wrappers. The resulting EXE requires the runtime.

---

## Project Files

### Format (.rxproj)
```
# RawrXD Project File
version=1.0
main=main.asm
output=program.exe
```

### Creating Projects
```batch
; Create new project
RawrXD-IDE-v5.exe
File → New Project

; Save project
File → Save Project
```

---

## Troubleshooting

### "Compiler not found"
**Solution**: Add RawrXD bin directory to PATH

### "Missing runtime"
**Solution**: Install required runtime (Python, Node.js, etc.)

### "Assembly failed"
**Check**:
1. Syntax errors in source
2. File encoding (must be UTF-8 or ASCII)
3. Instruction support

### "Linking failed"
**Check**:
1. Object file exists
2. Entry point defined (_start or main)
3. No unresolved symbols

---

## Advanced Topics

### Bootstrap Build
```batch
cd bootstrap
bootstrap.bat
```

### Self-Hosting
The toolchain can rebuild itself:
1. Use MinGW/gcc to build seed
2. Use seed to build self
3. Verify output matches

### Custom Compilers
Create your own compiler:
1. Write parser
2. Generate C wrapper
3. Compile with gcc
4. Integrate with CLI

---

## Support

For issues and questions:
- Documentation: `docs\`
- Examples: `examples\`
- Tests: `rawrxd_ide_cli_v3.bat test`

---

**END OF USER MANUAL**
