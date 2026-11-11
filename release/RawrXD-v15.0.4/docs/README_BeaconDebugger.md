# RawrXD Beacon Debugger v1.0
## Pure x64 MASM | Zero CRT | Zero External Dependencies

### Overview

The **RawrXD Beacon Debugger** is a fully-functional Windows debugger written entirely in x64 MASM assembly language. It has **zero dependencies** on the C runtime (CRT), C++ STL, or any external libraries beyond `kernel32.dll` and `ntdll.dll`.

### Features

| Feature | Status | Description |
|---------|--------|-------------|
| **Process Attach** | ✅ | Attach to running process by PID |
| **Process Creation** | ✅ | Create and debug new process |
| **Software Breakpoints** | ✅ | INT 3 injection with original byte restoration |
| **Single Stepping** | ✅ | Trap Flag manipulation via CONTEXT |
| **Step Over** | ✅ | Breakpoint at next instruction |
| **Register Display** | ✅ | All 17 x64 registers + EFLAGS |
| **Memory Dump** | ✅ | Byte/Dword/Qword with ASCII |
| **Memory Edit** | ✅ | Byte/Dword/Qword write |
| **Disassembly** | ✅ | x64 instruction length decoder + mnemonic lookup |
| **Debug Event Loop** | ✅ | WaitForDebugEventEx + ContinueDebugEvent |

### Build

```batch
ml64.exe /c /nologo /W3 /Fo beacon.obj RawrXD_BeaconDebugger.asm
link /nologo /subsystem:console /entry:main /out:beacon.exe beacon.obj kernel32.lib ntdll.lib
```

Or use the provided `build_beacon.bat`.

### Usage

```
beacon.exe                    ; Interactive mode
beacon.exe attach 1234        ; Auto-attach to PID 1234
beacon.exe run notepad.exe    ; Auto-run and debug notepad
```

### Commands

| Command | Description |
|---------|-------------|
| `attach <pid>` | Attach to running process |
| `run <exe> [args]` | Create and debug new process |
| `b <addr>` | Set software breakpoint (INT 3) |
| `bc <index>` | Clear breakpoint |
| `bl` | List breakpoints |
| `g` | Go / continue execution |
| `t` | Trace / step into (sets Trap Flag) |
| `p` | Step over (breakpoints next instruction) |
| `r` | Show all x64 registers |
| `db <addr> [len]` | Dump bytes (default 64) |
| `dd <addr> [len]` | Dump dwords |
| `dq <addr> [len]` | Dump qwords |
| `eb <addr> <val>` | Edit byte |
| `ed <addr> <val>` | Edit dword |
| `eq <addr> <val>` | Edit qword |
| `u <addr> [len]` | Unassemble (default 10 instructions) |
| `q` | Quit / detach |
| `?` | Show help |

### Architecture

- **Zero CRT**: No `printf`, no `sprintf`, no `malloc`, no `strlen`
- **No C++ STL**: No `std::string`, no `std::vector`
- **Windows API Only**: `kernel32.dll` + `ntdll.dll`
- **All structs manual**: `CONTEXT`, `DEBUG_EVENT`, `STARTUPINFOA`, `PROCESS_INFORMATION`, `EXCEPTION_RECORD`
- **All I/O manual**: `WriteFile`, `ReadFile` with custom hex/decimal/string formatters
- **Custom string routines**: `_strcmp`, `_strcpy`, `_strlen`, `_strtok`
- **Custom number parsing**: `_parse_hex`, `_parse_dec`
- **x64 instruction decoder**: `_insn_len` calculates instruction length for stepping
- **Minimal disassembler**: Opcode table lookup with mnemonic display

### Register Display

```
rax 0x00007FF6A1B2C3D4  rcx 0x0000000000000001  rdx 0x00007FF6A1B2E000
rbx 0x0000000000000000  rsp 0x0000005A3B2A1000  rbp 0x0000005A3B2A10F0
rsi 0x00007FF6A1B2C000  rdi 0x0000000000000000  rip 0x00007FF6A1B2C3E0
r8  0x0000000000000000  r9  0x0000000000000000  r10 0x0000000000000000
r11 0x0000000000000246  r12 0x0000000000000000  r13 0x0000000000000000
r14 0x0000000000000000  r15 0x0000000000000000  efl 0x00000202
```

### Memory Dump Format

```
0x00007FF6A1B2C3E0  48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48  H.$.H.t$.WH.. H
0x00007FF6A1B2C3F0  8B F1 48 8B DA 48 8B F9 48 8B CA E8 12 34 56 78  ..H..H..H...4Vx
```

### Breakpoint Handling

1. User sets breakpoint at address with `b <addr>`
2. Debugger reads original byte via `ReadProcessMemory`
3. Debugger writes `0xCC` (INT 3) via `WriteProcessMemory`
4. When breakpoint hits:
   - Exception is caught via `WaitForDebugEventEx`
   - Original byte is restored
   - RIP is decremented to re-execute original instruction
   - Registers are displayed
   - User can continue with `g`, step with `t`, or step over with `p`

### Single Stepping

1. User issues `t` (trace) command
2. Debugger sets Trap Flag (bit 8) in EFLAGS via `SetThreadContext`
3. `ContinueDebugEvent` resumes execution
4. CPU generates `EXCEPTION_SINGLE_STEP` after next instruction
5. Debugger displays registers and waits for next command

### Step Over

1. User issues `p` (step over) command
2. Debugger calculates length of current instruction via `_insn_len`
3. Debugger sets breakpoint at next instruction
4. Continues execution
5. When breakpoint hits, displays registers

### Instruction Length Calculation

The `_insn_len` procedure decodes x64 instructions:
1. Skip REX prefixes (0x40-0x4F)
2. Skip legacy prefixes (0x66, 0x67, 0xF0, 0xF2, 0xF3, segment overrides)
3. Decode opcode:
   - Single-byte: lookup in `opcode_flags` table
   - Two-byte (0x0F): lookup in `ext0F_flags` table
4. If ModR/M present: decode mod, reg, r/m fields
5. If SIB present: decode scale, index, base
6. Add displacement (0, 1, 4 bytes based on mod)
7. Add immediate (0, 1, 2, 4, 8 bytes based on opcode)

### Limitations

- **No hardware breakpoints** — Dr0-Dr3 not wired yet (can add ~200 lines)
- **No call stack unwinding** — Requires PDB parsing or RBP chain walking
- **No symbol resolution** — Raw addresses only, no PDB parsing
- **Minimal disassembler** — ~100 common opcodes, not exhaustive x64 decode
- **Single thread focus** — Multi-thread event handling exists but no thread switch UI
- **No conditional breakpoints** — Simple INT 3 only
- **No watchpoints** — No memory access breakpoints

### File Structure

```
d:\rawrxd\src\asm\
├── RawrXD_BeaconDebugger.asm    # Main source (3000 lines)
└── beacon.exe                    # Output executable

d:\rawrxd\scripts\
└── build_beacon.bat              # Build script
```

### Statistics

- **Total Lines**: 3000
- **Code Size**: ~15KB assembled
- **Data Size**: ~5KB (tables, strings, buffers)
- **Stack Usage**: Minimal (all buffers in .data)
- **External Dependencies**: 2 DLLs (kernel32, ntdll)
- **CRT Dependencies**: 0

### Security Considerations

- Requires `SeDebugPrivilege` for attaching to arbitrary processes
- Can read/write arbitrary process memory (dangerous)
- Can modify arbitrary process execution (dangerous)
- Use only on processes you own or have permission to debug

### Future Enhancements

- Hardware breakpoint support (DR0-DR3 registers)
- Call stack unwinding (RBP chain or unwind info)
- Symbol resolution (PDB parsing)
- Memory map display (VirtualQueryEx)
- Module listing (PEB traversal)
- Thread listing and switching
- Conditional breakpoints
- Memory watchpoints (page guard)
- Remote debugging (TCP/IP)

### License

This is part of the RawrXD project. Use at your own risk.

---

**RawrXD Beacon Debugger v1.0**  
**Pure x64 MASM | Zero CRT | Fully Functional**  
**Date**: 2026-06-21
