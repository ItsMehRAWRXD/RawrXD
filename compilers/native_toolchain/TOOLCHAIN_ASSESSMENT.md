# Native Toolchain Status Report

**Date:** 2026-07-07  
**Location:** `d:\rawrxd\compilers\native_toolchain\`

## Executive Summary

There are **TWO** native toolchain implementations:

### 1. C-Based Toolchain (PARTIALLY COMPLETE)
**Location:** `d:\rawrxd\compilers\native_toolchain\`  
**Language:** C  
**Status:** 70% complete

| Component | Lines | Status | What Works | What's Missing |
|-----------|-------|--------|------------|----------------|
| **Assembler** | 2,210 | 80% | Instruction encoding, label resolution, PE output | COFF object output |
| **Linker** | 987 | 60% | COFF reading, symbol resolution | PE generation has bugs |
| **Librarian** | 554 | 50% | Archive format | Symbol table |
| **RC Compiler** | ~400 | 40% | Resource parsing | Resource compilation |

### 2. MASM-Based Toolchain (SCAFFOLDING ONLY)
**Location:** `d:\rawrxd\compilers\native_tools\`  
**Language:** MASM Assembly  
**Status:** 10% complete (proof of concept)

| Component | Lines | Status | What Works | What's Missing |
|-----------|-------|--------|------------|----------------|
| **Assembler** | 600 | 10% | Prints banner | Everything else |
| **Linker** | 560 | 10% | Prints banner | Everything else |
| **Librarian** | 400 | 10% | Prints banner | Everything else |
| **RC Compiler** | 380 | 10% | Prints banner | Everything else |

## The Critical Gap

**C-Based Assembler:**
- ✅ Parses 500+ instruction mnemonics
- ✅ Encodes x86/x64 instructions correctly
- ✅ Resolves labels and fixups
- ✅ Generates PE executables directly
- ❌ **Cannot output COFF object files** (TODO comment in code)

**C-Based Linker:**
- ✅ Reads COFF object files
- ✅ Resolves symbols
- ❌ **Cannot link because assembler doesn't produce COFF**

**The assembler and linker are incompatible:**
- Assembler outputs PE executables (MZ header)
- Linker expects COFF objects (machine type header)
- Result: Linker fails with "Unknown machine type 0x0003"

## What Actually Works

### Assembler (rawrxd_native_assembler.exe)
```bash
# This WORKS - produces PE executable directly
rawrxd_native_assembler.exe test.asm test.exe

# This FAILS - COFF output not implemented
rawrxd_native_assembler.exe /c test.asm test.obj
# Error: Object file output not yet implemented
```

**Test Results:**
- ✅ Parses `mov rax, 0x123456789ABCDEF0`
- ✅ Encodes `add rax, rbx`
- ✅ Resolves labels (`jmp label`)
- ✅ Generates working PE executable
- ❌ Cannot produce .obj files for linker

### Linker (rawrxd_native_linker.exe)
```bash
# This FAILS - cannot read ML64 output
rawrxd_native_linker.exe test.obj /out:test.exe
# Error: Unknown machine type 0x0003

# This would work IF assembler produced COFF
rawrxd_native_linker.exe assembler_output.obj /out:program.exe
```

**Test Results:**
- ✅ Reads COFF header
- ✅ Parses section headers
- ✅ Builds symbol table
- ❌ Machine type check fails (expects 0x8664, gets 0x0003)

## Instruction Coverage (C-Based Assembler)

The assembler has **extensive instruction tables**:

### General Purpose (✅ Complete)
- Data movement: `mov`, `push`, `pop`, `xchg`, `lea`
- Arithmetic: `add`, `sub`, `adc`, `sbb`, `inc`, `dec`, `neg`, `mul`, `imul`, `div`, `idiv`
- Logical: `and`, `or`, `xor`, `not`
- Shifts: `shl`, `shr`, `sar`, `rol`, `ror`
- Comparison: `cmp`, `test`

### Control Flow (✅ Complete)
- Unconditional: `jmp`, `call`, `ret`
- Conditional: `je`, `jne`, `jl`, `jle`, `jg`, `jge`, `ja`, `jae`, `jb`, `jbe`, `js`, `jns`, `jo`, `jno`
- Loops: `loop`, `loope`, `loopne`
- Set on condition: `sete`, `setne`, `setl`, `setg`, etc.

### System (✅ Complete)
- `syscall`, `sysret`, `int`, `int3`, `cli`, `sti`, `hlt`, `nop`
- `cpuid`, `rdtsc`, `rdmsr`, `wrmsr`
- Memory barriers: `lfence`, `sfence`, `mfence`

### String Operations (✅ Complete)
- `movsb`, `movsw`, `movsd`, `movsq`
- `stosb`, `stosw`, `stosd`, `stosq`
- `lodsb`, `lodsw`, `lodsd`, `lodsq`
- `scasb`, `scasw`, `scasd`, `scasq`
- `cmpsb`, `cmpsw`, `cmpsd`, `cmpsq`
- Repeat prefixes: `rep`, `repe`, `repne`

### Bit Operations (✅ Complete)
- `bt`, `bts`, `btr`, `btc`
- `bsf`, `bsr`, `bswap`

### AVX/SSE (❌ NOT IMPLEMENTED)
- No AVX instructions (`vpbroadcastd`, `vpsrldq`, etc.)
- No SSE instructions (`movaps`, `addps`, etc.)
- No AVX-512 instructions

## What Needs to Be Done

### Priority 1: COFF Object Output (CRITICAL)
**File:** `rawrxd_native_assembler.c`  
**Function:** `write_coff_file()` (currently just a TODO comment)

```c
// Current code:
/* TODO: COFF object file output */
write_pe_file(output_file);

// Need to implement:
void write_coff_file(const char *filename) {
    // Write COFF header (20 bytes)
    // Write section headers (40 bytes each)
    // Write section data
    // Write relocation table
    // Write symbol table
    // Write string table
}
```

**Estimated effort:** 200-300 lines of code

### Priority 2: Fix Linker Machine Type Check
**File:** `rawrxd_native_linker.c`  
**Issue:** Linker rejects valid COFF files

```c
// Current code:
if (coff->Header.Machine == IMAGE_FILE_MACHINE_AMD64) {
    // x64
} else if (coff->Header.Machine == IMAGE_FILE_MACHINE_I386) {
    // x86
} else {
    fprintf(stderr, "Error: Unknown machine type 0x%04X\n", coff->Header.Machine);
    return 0;
}
```

The error shows machine type 0x0003, which is invalid. This suggests the COFF reader is broken.

### Priority 3: Add AVX/SSE Instructions
**File:** `rawrxd_native_assembler.c`  
**Missing:** ~500 AVX/SSE instructions

```c
// Need to add:
{"vpbroadcastd", {0xC4, 0xE2, 0x7D, 0x58}, 4, OP_YMM, OP_MEM32, ...},
{"vpsrldq", {0xC5, 0xF9, 0x73}, 3, OP_XMM, OP_XMM, OP_IMM8, ...},
{"vfmadd213ps", {0xC4, 0xE2, 0x6D, 0xA8}, 4, OP_YMM, OP_YMM, ...},
// ... 500+ more
```

**Estimated effort:** 1000-2000 lines of instruction tables

## Test Cases

### Working Test
```asm
; test.asm - Assembles and runs correctly
.code
_start:
    mov rax, 0x123456789ABCDEF0
    mov rbx, rax
    add rax, rbx
    sub rax, 100
    jmp exit_label
    nop
exit_label:
    xor rax, rax
    ret
```

```bash
rawrxd_native_assembler.exe test.asm test.exe
./test.exe  # Works!
```

### Failing Test
```asm
; test_avx.asm - Fails (AVX not implemented)
.code
_start:
    vpbroadcastd ymm0, [rdx]
    vpsrldq xmm1, xmm0, 4
    ret
```

```bash
rawrxd_native_assembler.exe test_avx.asm test_avx.exe
# Error: Unknown instruction 'vpbroadcastd'
```

## Recommendation

**Use the C-based toolchain as the foundation:**

1. **Implement COFF output** in `rawrxd_native_assembler.c` (200-300 lines)
2. **Fix linker** to read COFF correctly (debug machine type issue)
3. **Add AVX/SSE instructions** to instruction tables (1000-2000 lines)
4. **Test with real kernel files** from `d:\rawrxd\src\asm\`

The MASM-based toolchain I just built is **not worth pursuing** - it's just scaffolding. The C-based toolchain has real instruction encoding and is 70% complete.

## Files to Focus On

```
d:\rawrxd\compilers\native_toolchain\
├── rawrxd_native_assembler.c   # Add write_coff_file()
├── rawrxd_native_linker.c      # Fix COFF reading
├── rawrxd_native_librarian.c   # Implement archive format
└── rawrxd_native_rc.c          # Implement resource compilation
```

## Next Steps

1. Implement `write_coff_file()` in assembler
2. Debug linker's COFF reader
3. Test: `rawrxd_native_assembler.exe /c test.asm test.obj && rawrxd_native_linker.exe test.obj /out:test.exe`
4. Add AVX/SSE instruction tables
5. Test with real `.asm` files from kernel

---

**Bottom Line:** The C-based toolchain is 70% complete and has real instruction encoding. The MASM-based toolchain I just built is 10% scaffolding. Focus on completing the C-based toolchain.