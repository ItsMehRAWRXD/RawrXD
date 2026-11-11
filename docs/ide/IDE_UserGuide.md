# Sovereign IDE User Guide
## Complete User Documentation

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete  

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Main Interface](#main-interface)
3. [Explorer Panel](#explorer-panel)
4. [Editor](#editor)
5. [Output Panel](#output-panel)
6. [MoE Panels](#moe-panels)
7. [Reverse Engineering Panels](#reverse-engineering-panels)
8. [Security Analysis Panels](#security-analysis-panels)
9. [Integration Panel](#integration-panel)
10. [Telemetry Panel](#telemetry-panel)
11. [Keyboard Shortcuts](#keyboard-shortcuts)
12. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Launching the IDE

```batch
# From command line
d:\rawrxd\bin\SovereignIDE.exe

# With file argument
d:\rawrxd\bin\SovereignIDE.exe target.exe

# With project
d:\rawrxd\bin\SovereignIDE.exe project.sov
```

### First Launch

On first launch, the IDE will:
1. Initialize the Sovereign Kernel
2. Load all 40 subsystems
3. Execute integration phases
4. Display the main interface

### Quick Tour

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Menu Bar (File, View, Tools, MoE, Help)                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────┐ ┌──────────────────────────────────────────────────────────┐   │
│  │ Explorer │ │ Editor                                                  │   │
│  │          │ │                                                         │   │
│  │ - Files  │ │ [Code/Disassembly/Decompilation view]                │   │
│  │ - Symbols│ │                                                         │   │
│  │ - Types  │ │                                                         │   │
│  └──────────┘ └──────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│  [Output] [MoE Output] [Diagnostics] [Debugger] [Heatmap] [Integration]     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Main Interface

### Menu Bar

#### File Menu
- **New** → Create new file/project
- **Open** → Open existing file
- **Open Project** → Open .sov project file
- **Save** → Save current file
- **Save All** → Save all open files
- **Exit** → Close IDE

#### View Menu
- **Explorer** → Toggle file explorer
- **MoE Output** → Show MoE trace panel
- **Diagnostics** → Show diagnostics panel
- **Debugger** → Show debugger panel
- **Heatmap** → Show activation heatmap
- **Spec Explorer** → Show speculation tree
- **Integration** → Show integration status

#### Tools Menu
- **MASM Editor** → Open MASM editor
- **Build** → Build current project
- **Clean** → Clean build artifacts
- **Options** → IDE preferences

#### MoE Menu
- **Generate** → Run MoE generation
- **View Trace** → Show execution trace
- **Swarm Mode** → Enable swarm reasoning
- **Ghost Mode** → Enable ghost text

### Toolbar

```
[New] [Open] [Save] | [Build] [Run] [Debug] | [MoE Generate] [Trace] | [Help]
```

### Status Bar

```
Ready | Line 1, Col 1 | UTF-8 | Windows (CRLF) | MoE: Active | Subsystems: 40/40
```

---

## Explorer Panel

### File Explorer

Displays project files in tree view:

```
📁 Project
├── 📁 src
│   ├── 📄 main.cpp
│   └── 📄 utils.cpp
├── 📁 include
│   └── 📄 utils.h
├── 📄 Makefile
└── 📄 README.md
```

**Context Menu:**
- Open
- Open With → [Hex Editor | Disassembler]
- Analyze → [Binary | Malware | Firmware]
- Properties

### Symbol Explorer

Displays symbols from loaded binary:

```
Symbols
├── Functions (1,234)
│   ├── main
│   ├── printf
│   └── ...
├── Imports (45)
│   ├── kernel32.dll
│   └── ...
├── Exports (12)
│   └── ...
└── Strings (5,678)
    └── ...
```

### Type Explorer

Displays data types:

```
Types
├── Structures (23)
│   ├── PE_HEADER
│   └── ...
├── Enumerations (15)
│   └── ...
└── Typedefs (8)
    └── ...
```

---

## Editor

### Code Editor

Features:
- Syntax highlighting (C, C++, MASM, Python)
- Auto-indentation
- Line numbers
- Code folding
- Find/Replace (Ctrl+F)
- Go to Definition (F12)

### Hex Editor

For binary files:

```
Offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F    ASCII
00000000  4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00    MZ..............
00000010  B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......
```

### Disassembly View

```
Address    Bytes        Instruction
00401000   55           push    ebp
00401001   8B EC        mov     ebp, esp
00401003   6A 00        push    0
00401005   68 00 30 40  push    offset aHelloWorld
           00
```

### Decompiler View

```c
int __cdecl main(int argc, const char **argv) {
    printf("Hello, World!\n");
    return 0;
}
```

---

## Output Panel

### Build Output

```
[Build] Starting build...
[Build] Compiling main.cpp...
[Build] Compiling utils.cpp...
[Build] Linking...
[Build] Build succeeded in 2.34s
```

### Debug Output

```
[Debug] Attached to process 1234
[Debug] Breakpoint hit at 0x00401000
[Debug] Registers:
  EAX: 0x00000000  EBX: 0x00000000
  ECX: 0x00000000  EDX: 0x00000000
```

### Search Results

```
Search: "memcpy"
Found 12 results:
  main.cpp:45    memcpy(dst, src, len);
  utils.cpp:12   memcpy(buffer, data, size);
  ...
```

---

## MoE Panels

### MoE Output Panel

Displays real-time MoE execution traces:

```
Timestamp    Expert      Token    Confidence    Latency
─────────────────────────────────────────────────────────
12:34:56.123 Ghost       "int"    0.95          5ms
12:34:56.128 Ghost       "main"   0.92          4ms
12:34:56.134 Swarm       "("      0.88          8ms
12:34:56.142 Latent      "void"   0.90          3ms
```

### MoE Diagnostics Panel

```
Router Latency:     1.2ms
Confidence Average: 0.91
KV Density Average: 0.78
Expert Executions:  1,234
Active Experts:     5/128
```

### MoE Debugger Panel

```
Current Expert: Ghost
Current Token: "printf"
Router Step:   42
KV Density:    0.85
Confidence:    0.94

[Step] [Continue] [Reset]
```

### MoE Heatmap Panel

Visualizes expert activation patterns:

```
    0   1   2   3   4   5   6   7
  ┌───┬───┬───┬───┬───┬───┬───┬───┐
0 │███│██░│█░░│░░░│░░░│░░░│░░░│░░░│
1 │███│███│██░│█░░│░░░│░░░│░░░│░░░│
2 │███│███│███│██░│██░│█░░│░░░│░░░│
3 │░░░│░░░│░░░│░░░│███│███│██░│█░░│
...
```

### MoE Spec Explorer Panel

Displays speculation tree:

```
[Root]
├── Ghost (0.95)
│   ├── "int" (0.92)
│   ├── "void" (0.88)
│   └── "char" (0.75)
├── Swarm (0.91)
│   ├── "main" (0.89)
│   └── "printf" (0.85)
└── Latent (0.87)
    └── ...
```

---

## Reverse Engineering Panels

### Binary Analysis Panel

```
File: target.exe
Format: PE32+ (x64)
Entry Point: 0x00001400
Image Base: 0x0000000140000000

Sections:
  .text  - RVA: 0x1000  Size: 0x5000  Exec
  .data  - RVA: 0x6000  Size: 0x2000  RW
  .rsrc  - RVA: 0x8000  Size: 0x1000  R
```

### CFG Viewer

Graphical control flow graph:

```
    [Entry]
       │
       ▼
   [Block 1]
   /        \
  ▼          ▼
[Block 2]  [Block 3]
  │          │
  └────┬─────┘
       ▼
   [Block 4]
       │
       ▼
    [Exit]
```

### Debugger Panel

```
Process: target.exe (PID: 1234)
Status: Paused at 0x00401000

Registers:
  RAX: 0x0000000000000000
  RBX: 0x0000000000000000
  RCX: 0x0000000000000000
  RDX: 0x0000000000000000
  RIP: 0x0000000000401000
  RSP: 0x000000000014FF00
  RBP: 0x000000000014FF00

[Step Into] [Step Over] [Continue] [Break]
```

### Memory View Panel

```
Address            00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000000014FF00  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000000000014FF10  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

---

## Security Analysis Panels

### Malware Analysis Panel

```
File: suspicious.exe
Threat Level: HIGH

Detections:
  ✓ Packed with UPX
  ✓ Suspicious imports
  ✓ C2 communication detected

Behavior:
  • Creates process: svchost.exe
  • Connects to: 192.168.1.100:4444
  • Writes to: %TEMP%\malware.dll

[Unpack] [Analyze Behavior] [Generate Report]
```

### Protocol Viewer Panel

```
Packet #1 - TCP
  Source: 192.168.1.5:54321
  Dest:   192.168.1.100:80
  Size:   64 bytes
  Protocol: HTTP

Payload:
GET /index.html HTTP/1.1
Host: example.com

[Analyze] [Follow Stream] [Export]
```

### State Machine Viewer

```
        ┌─────────┐
   ┌───►│  IDLE   │◄───┐
   │    └────┬────┘    │
   │         │         │
   │    SYN  │         │ RST
   │         ▼         │
   │    ┌─────────┐    │
   └────┤SYN_SENT │────┘
        └────┬────┘
             │ SYN-ACK
             ▼
        ┌─────────┐
        │ESTABLISH│
        └────┬────┘
             │
             ▼
           ...
```

### Crypto Analysis Panel

```
Encryption Detected: TLS 1.3
Cipher Suite: TLS_AES_256_GCM_SHA384
Key Exchange: ECDHE
Certificate: Valid

Entropy Analysis:
  Before: 4.2 bits/byte
  After:  7.8 bits/byte

[Decrypt] [Analyze Certificate] [Export Keys]
```

### Fuzzing Panel

```
Target: protocol_handler.exe
Strategy: Random Mutation
Iterations: 1,000 / 10,000
Coverage: 45%

Crashes Found: 2
  • Crash #1: Access Violation at 0x00401234
  • Crash #2: Stack Overflow at 0x00401567

[Pause] [Stop] [Export Results]
```

### Exploit Surface Map

```
Vulnerabilities Found: 5

Severity Distribution:
  Critical: 1 ████
  High:     2 ████████
  Medium:   1 ████
  Low:      1 ████

Attack Vectors:
  • Buffer Overflow (memcpy)
  • Format String (printf)
  • Integer Overflow (malloc)

[Generate Exploit] [View Details]
```

---

## Integration Panel

### Integration Status

```
SOVEREIGN INTEGRATION STATUS

Phase 1: ABI Verification     ✅ 40/40 batches
Phase 2: SEG Linkage           ✅ 256/256 nodes
Phase 3: MoE Registration      ✅ 128/128 experts
Phase 4: Subsystem Binding     ✅ 40/40 subsystems
Phase 5: Cross-Connect         ✅ 512/512 routes
Phase 6: GUI Binding           ✅ 64/64 panels
Phase 7: Artifact Scanner        ✅ 40/40 artifacts
Phase 8: Validation            ✅ All tests passed
Phase 9: Runtime Ready         ✅ Active

Overall: 100% Complete ✅
```

### Subsystem Health

```
Subsystem              Status    Health    Last Check
─────────────────────────────────────────────────────
Core Kernel            ✅        100%      12:34:56
MoE Router             ✅        100%      12:34:56
SEG Engine             ✅        100%      12:34:56
Binary Analysis        ✅        100%      12:34:56
Debugger               ✅        100%      12:34:56
Malware Analysis       ✅        100%      12:34:56
Network Protocol       ✅        100%      12:34:56
Exploit Development    ✅        100%      12:34:56
```

---

## Telemetry Panel

### Execution Journal

```
Time     Event                          Duration
─────────────────────────────────────────────────
12:34:50 IDE Startup                    1.2s
12:34:52 Kernel Initialized             0.5s
12:34:53 Subsystems Loaded              2.1s
12:34:56 Integration Complete           0.8s
12:35:00 File Opened: target.exe        0.3s
12:35:05 Analysis Started               5.2s
12:35:10 Analysis Complete              0.1s
```

### Performance Metrics

```
CPU Usage:    15%
Memory:       512 MB / 2048 MB
Disk I/O:     45 MB/s
Network:      0 KB/s

Subsystem Latencies:
  MoE Router:     1.2ms
  SEG Engine:     0.5ms
  Binary Load:   50.0ms
  Malware Scan: 100.0ms
```

---

## Keyboard Shortcuts

### General

| Shortcut | Action |
|----------|--------|
| Ctrl+N | New file |
| Ctrl+O | Open file |
| Ctrl+S | Save file |
| Ctrl+Shift+S | Save all |
| Ctrl+Z | Undo |
| Ctrl+Y | Redo |
| Ctrl+F | Find |
| Ctrl+H | Replace |
| Ctrl+G | Go to line |
| F1 | Help |
| F5 | Build |
| F9 | Toggle breakpoint |
| F10 | Step over |
| F11 | Step into |
| F12 | Go to definition |

### Navigation

| Shortcut | Action |
|----------|--------|
| Ctrl+Tab | Next tab |
| Ctrl+Shift+Tab | Previous tab |
| Ctrl+W | Close tab |
| Ctrl+1-9 | Go to tab N |
| Ctrl+B | Toggle explorer |
| Ctrl+J | Toggle output |
| Ctrl+` | Toggle terminal |

### MoE

| Shortcut | Action |
|----------|--------|
| Ctrl+M | MoE generate |
| Ctrl+Shift+M | Toggle MoE panel |
| Ctrl+T | View trace |
| Ctrl+R | Reset MoE |

---

## Troubleshooting

### IDE Won't Start

1. Check that all subsystems are built
2. Verify integration completed successfully
3. Check Windows Event Viewer for errors
4. Run with `-debug` flag for verbose output

### MoE Not Responding

1. Check MoE backend is loaded
2. Verify MoE.dll exists in bin directory
3. Check subsystem health in Integration panel
4. Restart IDE

### Build Failures

1. Check compiler is installed (VS2022 or MinGW)
2. Verify tool paths in build configuration
3. Check for missing source files
4. Review build output for errors

### Performance Issues

1. Check system resources (CPU, memory)
2. Disable unnecessary panels
3. Reduce MoE expert count
4. Enable performance mode in options

---

## Summary

The Sovereign IDE provides:

- ✅ **Intuitive interface**
- ✅ **Comprehensive panels**
- ✅ **Keyboard shortcuts**
- ✅ **Extensive documentation**
- ✅ **Troubleshooting guide**

**Status:** ✅ Ready for use

---

*End of IDE User Guide*
