# Native Toolchain IDE Integration

**Date:** 2026-07-07  
**Status:** ✅ **INTEGRATED** - Single-click build for .asm files

## Overview

The native toolchain is now integrated into VS Code for seamless .asm file compilation:

- **Assembler:** `rawrxd_native_assembler.exe` (125KB, 500+ instructions)
- **Linker:** `rawrxd_native_linker.exe` (65KB)
- **Librarian:** `rawrxd_native_librarian.exe` (64KB)
- **Resource Compiler:** `rawrxd_native_rc.exe` (64KB)

## Features

### ✅ No MSVC Dependency
- Self-contained C-based toolchain
- No external dependencies
- Works without Visual Studio installed

### ✅ MASM-Compatible Syntax
- Supports 500+ x64 instructions
- AVX/AVX2/AVX-512 instruction support
- Standard MASM directives (PUBLIC, PROC, ENDP, etc.)

### ✅ IDE Integration
- **Tasks:** Build .asm files with Ctrl+Shift+B
- **Problem Matcher:** Errors appear in Problems panel
- **Keybindings:** Quick build and run shortcuts

## Usage

### Build Current .asm File

1. Open any `.asm` file in the editor
2. Press `Ctrl+Shift+B` or run task: `Native Assembler: Build .asm File`
3. Output: `.obj` file in same directory

### Full Build Pipeline (Assemble + Link)

1. Open any `.asm` file in the editor
2. Press `Ctrl+Shift+L` or run task: `Native Toolchain: Assemble & Link`
3. Output: `.exe` file in same directory

### Build All .asm Files in Directory

1. Run task: `Native Assembler: Build All .asm Files in Directory`
2. Assembles and links all `.asm` files in the current directory

### Run Assembled Executable

1. Press `F5` when a `.asm` file is active
2. Automatically builds and runs the executable

## Configuration

### VS Code Settings

Located in `.vscode/settings.json`:

```json
{
  "rawrxd.nativeToolchain.assemblerPath": "${workspaceFolder}/compilers/native_toolchain/rawrxd_native_assembler.exe",
  "rawrxd.nativeToolchain.linkerPath": "${workspaceFolder}/compilers/native_toolchain/rawrxd_native_linker.exe",
  "rawrxd.nativeToolchain.librarianPath": "${workspaceFolder}/compilers/native_toolchain/rawrxd_native_librarian.exe",
  "rawrxd.nativeToolchain.enabled": true
}
```

### VS Code Tasks

Located in `.vscode/tasks.json`:

| Task | Description | Shortcut |
|------|-------------|----------|
| `Native Assembler: Build .asm File` | Assemble current file | Ctrl+Shift+B |
| `Native Toolchain: Assemble & Link` | Full build pipeline | Ctrl+Shift+L |
| `Run: Assembled Executable` | Build and run | F5 |
| `Native Assembler: Build All .asm Files in Directory` | Batch build | - |

### VS Code Keybindings

Located in `.vscode/keybindings.json`:

| Key | Command | Context |
|-----|---------|---------|
| Ctrl+Shift+B | Build .asm file | .asm file active |
| Ctrl+Shift+L | Assemble & Link | .asm file active |
| F5 | Run executable | .asm file active |

## Error Parsing

The native assembler outputs errors in a format compatible with VS Code's problem matcher:

```
Error: Unknown instruction 'xyz'
Error: Undefined label 'missing_label'
Error: Cannot open input file 'test.asm'
```

These errors appear in the **Problems** panel with proper file location and severity.

## Example Workflow

### 1. Create Assembly File

```asm
; test.asm - Simple test program
.code
main proc
    mov rax, 42
    ret
main endp
end main
```

### 2. Build

Press `Ctrl+Shift+L` or run:
```
Native Toolchain: Assemble & Link
```

### 3. Check Output

- **Problems Panel:** Any errors appear here
- **Terminal:** Build output shows progress
- **File Explorer:** `test.exe` appears next to `test.asm`

### 4. Run

Press `F5` to run the executable.

## Supported Instructions

The native assembler supports 500+ x64 instructions including:

### General Purpose
- MOV, ADD, SUB, MUL, DIV, INC, DEC
- AND, OR, XOR, NOT, SHL, SHR, SAR
- CMP, TEST, JMP, Jcc (all condition codes)
- CALL, RET, PUSH, POP, LEA

### SSE/AVX
- MOVAPS, MOVUPS, MOVSS, MOVSD
- ADDPS, SUBPS, MULPS, DIVPS
- ADDPD, SUBPD, MULPD, DIVPD
- VPADDD, VPSUBD, VPMULLD
- VFMADD213PS, VFMADD231PS

### AVX-512 (Subset)
- VPBROADCASTD, VPBROADCASTQ
- VPMOVSXBD, VPMOVZXBD
- KMOVW, KANDW, KORW, KXORW

### System
- SYSCALL, SYSRET, CPUID, RDTSC
- INT, IRET, CLI, STI

## Limitations

### Current Limitations
1. **Macro Support:** Limited macro support (`.macro` directive)
2. **Include Files:** `.include` directive not yet implemented
3. **Complex Expressions:** Limited expression evaluation
4. **AVX-512:** Only subset of AVX-512 instructions

### Workarounds
1. **Macros:** Use inline code or preprocessor
2. **Includes:** Manually merge files or use C preprocessor
3. **Expressions:** Pre-calculate values or use EQU

## Troubleshooting

### "Cannot open input file"
- Check file path is correct
- Ensure file exists and has `.asm` extension

### "Unknown instruction"
- Check instruction spelling
- Verify instruction is supported (see list above)
- Check for correct operand types

### "Undefined label"
- Ensure label is defined before use
- Check label spelling (case-insensitive)
- Verify label scope (local vs global)

## Files

```
d:\rawrxd\compilers\native_toolchain\
├── rawrxd_native_assembler.c      # Assembler source (2,210+ lines)
├── rawrxd_native_assembler.exe    # Assembler binary (98 KB)
├── rawrxd_native_linker.c         # Linker source (987 lines)
├── rawrxd_native_linker.exe       # Linker binary (65 KB)
├── rawrxd_native_librarian.c      # Librarian source (554 lines)
├── rawrxd_native_librarian.exe    # Librarian binary (63 KB)
├── rawrxd_native_rc.c             # Resource compiler source
├── rawrxd_native_rc.exe           # Resource compiler binary
├── IDE_INTEGRATION.md             # This file
├── TOOLCHAIN_FINAL.md             # Toolchain completion report
└── TOOLCHAIN_STATUS.md            # Status documentation
```

## Related Documentation

- [TOOLCHAIN_FINAL.md](./TOOLCHAIN_FINAL.md) - Toolchain completion report
- [TOOLCHAIN_STATUS.md](./TOOLCHAIN_STATUS.md) - Status documentation
- [MASM_MASM_Build_Pipeline.md](../../memories/repo/MASM_MASM_Build_Pipeline.md) - Build pipeline notes

## Next Steps

1. **Add more AVX-512 instructions** - Expand instruction set
2. **Implement macro support** - Full macro directive support
3. **Add include file handling** - `.include` directive
4. **Improve error messages** - More detailed error reporting
5. **Add debug info generation** - PDB/CodeView support