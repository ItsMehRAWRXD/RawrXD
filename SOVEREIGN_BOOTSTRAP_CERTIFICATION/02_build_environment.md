# Sovereign Build Environment
## RawrXD Bootstrap Certification v1.0

**Date**: 2026-07-29  
**Environment**: Windows x64, BareMetal Toolchain  
**Target**: MSVC++ Independence

---

## Current Environment

### Host System
```
OS: Windows 11/Server 2025
Architecture: x86-64
CPU: AMD Ryzen/EPYC with AVX2/AVX-512
GPU: AMD Radeon RX 7800 XT 16GB + R9700 AI PRO 32GB
```

### External Dependencies (TO BE REMOVED)
| Tool | Current Use | Replacement | Status |
|------|-------------|-------------|--------|
| `cl.exe` | C/C++ compilation | `sovereign_cc.exe` | ⏳ Stage 1 |
| `link.exe` | PE linking | `sovereign_link.exe` | ✅ BareMetal PE Writer |
| `ml64.exe` | MASM assembly | `sovereign_asm.exe` | ✅ RawrCodex |
| `lib.exe` | Static libraries | `sovereign_lib.exe` | ⏳ Stage 2 |
| MSVC CRT | Runtime support | `sovereign_crt/` | ⏳ Stage 2 |
| MSVC STL | C++ standard library | `sovereign_std/` | ⏳ Stage 3 |

---

## Sovereign Toolchain Layout

### Directory Structure
```
D:\rawrxd\sovereign_toolchain\
│
├── bin\
│   ├── sovereign_cc.exe          # C compiler (Stage 1)
│   ├── sovereign_cxx.exe         # C++ compiler (Stage 3)
│   ├── sovereign_asm.exe         # MASM/NASM assembler
│   ├── sovereign_link.exe        # PE/ELF linker ✅
│   └── sovereign_build.exe       # Build orchestrator
│
├── lib\
│   ├── sovereign_crt.lib         # C runtime (Stage 2)
│   ├── sovereign_std.lib         # C++ standard library (Stage 3)
│   └── kernel32.lib              # Windows API imports
│
├── include\
│   ├── sovereign_crt\            # C headers
│   │   ├── stdio.h
│   │   ├── stdlib.h
│   │   ├── string.h
│   │   └── ...
│   │
│   ├── sovereign_std\             # C++ headers (Stage 3)
│   │   ├── vector
│   │   ├── string
│   │   ├── map
│   │   └── ...
│   │
│   └── intrinsics\               # Compiler intrinsics
│       ├── immintrin.h
│       ├── avx2.h
│       └── avx512.h
│
└── runtime\
    ├── crt0.asm                   # Startup code
    ├── heap.asm                   # Memory allocator
    ├── threads.asm                # Thread support
    └── exceptions.asm             # Exception handling
```

---

## Bootstrap Sequence

### Phase 0: Foundation (COMPLETE)
**Goal**: Prove PE generation works

```cmd
:: Verify BareMetal PE Writer
cd D:\rawrxd\temp_bootstrap
BareMetal_PE_Writer.exe
:: Creates: generated.exe (1,536 bytes)
generated.exe
:: Exit code: 42 ✅
```

**Artifacts**:
- `D:\rawrxd\BareMetal_PE_Writer.exe` (4,096 bytes)
- `D:\rawrxd\temp_bootstrap\generated.exe` (1,536 bytes)

---

### Phase 1: Compiler Bootstrap (NEXT)
**Goal**: Create working C compiler

```cmd
:: Use Genesis Self-Hosting to compile Solo Compiler
cd D:\rawrxd\src\asm

:: Step 1: Assemble compiler source
ml64.exe /c /Fo solo_standalone_compiler.obj solo_standalone_compiler.asm

:: Step 2: Link with PE Writer
link.exe /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:sovereign_cc.exe ^
    solo_standalone_compiler.obj ^
    kernel32.lib

:: Step 3: Test compiler
sovereign_cc.exe test.c -o test.exe
test.exe
:: Expected: Hello, Sovereign World!
```

**Target Artifacts**:
- `D:\rawrxd\sovereign_toolchain\bin\sovereign_cc.exe`
- Can compile simple C programs

---

### Phase 2: Self-Hosting (CRITICAL)
**Goal**: Compiler builds itself

```cmd
:: Use sovereign_cc to compile its own source
cd D:\rawrxd\sovereign_toolchain

sovereign_cc.exe ^
    ..\src\asm\solo_standalone_compiler.asm ^
    -o bin\sovereign_cc_v2.exe

:: Verify binary equivalence
fc /b bin\sovereign_cc.exe bin\sovereign_cc_v2.exe
:: Expected: No differences ✅
```

**Success Criteria**:
- Binary reproducibility
- Hash match between generations
- Functional equivalence

---

### Phase 3: RawrXD Runtime (FLAGSHIP)
**Goal**: Build RawrXD without MSVC

```cmd
:: Compile RawrXD runtime
cd D:\rawrxd

sovereign_build.exe rawrxd.sproj

:: Output:
::   bin\RawrXD.exe
::   bin\Deep2Gateway.exe
::   bin\SovereignRuntime.dll
```

**Verification**:
```cmd
:: Test executable
bin\RawrXD.exe --version
:: Expected: RawrXD v3.0.0 (Sovereign Build)

:: Verify no MSVC dependencies
dumpbin /dependents bin\RawrXD.exe
:: Expected: Only kernel32.dll, ntdll.dll, vulkan-1.dll
```

---

## Build Configuration

### rawrxd.sproj (Sovereign Project File)
```toml
[project]
name = "RawrXD"
version = "3.0.0"
type = "executable"

[toolchain]
compiler = "sovereign_cc"
assembler = "sovereign_asm"
linker = "sovereign_link"
crt = "sovereign_crt"

[architecture]
target = "x86_64"
features = ["avx2", "avx512", "fma"]

[sources]
cpp = [
    "src/runtime/*.cpp",
    "src/deep2/*.cpp",
    "src/inference/*.cpp"
]
asm = [
    "src/asm/SovereignKernels.asm",
    "src/asm/Runtime.asm"
]

[libraries]
link = ["kernel32", "vulkan-1"]

[options]
optimize = "O3"
debug = false
standalone = true  # No MSVC CRT
```

---

## Runtime Library Implementation

### crt0.asm (Entry Point)
```asm
; Sovereign C Runtime - Entry Point
; Replaces: mainCRTStartup

.code

start PROC FRAME
    ; Stack alignment
    sub rsp, 40h
    .allocstack 40h
    .endprolog
    
    ; Initialize heap
    call __sovereign_heap_init
    
    ; Initialize command line
    call __sovereign_parse_args
    
    ; Call main
    xor ecx, ecx        ; argc = 0 (simplified)
    xor edx, edx        ; argv = NULL
    call main
    
    ; Exit with return code
    mov ecx, eax
    call ExitProcess
    
start ENDP

END
```

### heap.asm (Memory Allocator)
```asm
; Sovereign Heap - Windows API only
; Replaces: malloc/free

.code

__sovereign_heap_init PROC
    ; Get process heap
    mov rcx, 0          ; GetProcessHeap takes no args
    call GetProcessHeap
    mov [g_heap], rax
    ret
__sovereign_heap_init ENDP

sovereign_malloc PROC
    ; rcx = size
    mov rdx, rcx
    mov rcx, [g_heap]
    xor r8, r8          ; flags = 0
    call HeapAlloc
    ret
sovereign_malloc ENDP

.data
    g_heap QWORD 0

END
```

---

## Verification Checklist

### Phase 0 ✅
- [x] BareMetal PE Writer executes
- [x] Generated PE runs (exit 42)
- [x] PE32+ format valid

### Phase 1 ⏳
- [ ] Solo Compiler assembles
- [ ] Links to executable
- [ ] Compiles simple C program
- [ ] Output runs correctly

### Phase 2 ⏳
- [ ] Compiler builds itself
- [ ] Binary reproducibility
- [ ] Hash match verified
- [ ] Functional equivalence

### Phase 3 ⏳
- [ ] RawrXD runtime compiles
- [ ] No MSVC dependencies
- [ ] Links successfully
- [ ] Runs inference
- [ ] IDE connects
- [ ] GPU acceleration works

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| C++ complexity | Start with C subset, add C++ gradually |
| STL replacement | Implement containers as needed by RawrXD |
| ABI compatibility | Test against existing object files |
| Performance | Profile and optimize critical paths |
| Debugging | Implement DWARF or PDB generation |

---

## Success Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Build time | < 5 minutes | N/A |
| Binary size | < 10% overhead | N/A |
| Performance | Within 5% of MSVC | N/A |
| Dependencies | kernel32 + ntdll only | N/A |
| Self-hosting | Yes | ⏳ |

---

**Next Document**: `03_compiler_build.log` (to be generated during Phase 1)
