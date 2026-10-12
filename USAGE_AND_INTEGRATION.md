# RawrXD Backend Designer - Complete Usage Guide

## Overview

You now have a **Split Architecture PE64 Backend** capable of:
1. **Fabricating** valid PE32+ executables from scratch
2. **Injecting** native machine code at runtime into any memory location
3. **Bridging** static and dynamic via absolute FF 25 jumps
4. **Resolving** APIs through PEB walking (zero import table)

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    SOVEREIGN BACKEND DESIGNER                   │
│                  (Split Fabricator-Injector)                    │
└─────────────────────────────────────────────────────────────────┘
         │                                              │
         ▼                                              ▼
┌────────────────────────┐                   ┌────────────────────────┐
│   PART 1: FABRICATOR   │                   │   PART 2: INJECTOR     │
│  (Static PE Geometry)  │                   │ (Dynamic Machine Code) │
├────────────────────────┤                   ├────────────────────────┤
│ Generate:              │                   │ Generate:              │
│ • DOS Header           │                   │ • Prologue (4 bytes)  │
│ • NT Headers           │                   │ • Native Payload      │
│ • Section Headers      │                   │ • Epilogue (5 bytes)  │
│ • Import Table         │                   │ • FF 25 bridge        │
│ • Export Table (opt.)  │                   │                        │
│ • PDATA/XDATA (opt.)   │                   │ Guarantees:           │
│ • Reloc Table (opt.)   │                   │ • Reversed stack      │
│                        │                   │ • Symmetric frame     │
│ Output:                │                   │ • 64-bit capable      │
│ Valid PE geometry      │                   │                        │
│ (1-4KB headers)        │                   │ Output:               │
└────────────────────────┘                   │ Native x64 opcodes    │
         │                                   │ (anywhere in memory)  │
         │              THE BRIDGE           └────────────────────────┘
         │           (FF 25 Jump)                     │
         │         ┌───────────────┐                  │
         │         │ FF 25 00 00 00│ 00              │
         │         │[64-bit Address]                  │
         │         │ JMP [RIP+0]   │                  │
         │         │ (14 bytes)    │                  │
         │         └───────────────┘                  │
         └─────────────┬──────────────────────────────┘
                       │
                       ▼
         ┌─────────────────────────────┐
         │   RUNTIME INTEGRATION       │
         ├─────────────────────────────┤
         │ 1. Fabricator → PE file     │
         │ 2. Injector → Memory buffer │
         │ 3. Bridge → Connect them    │
         │ 4. Resolver → PEB walk      │
         │ 5. Execute → Game patched   │
         └─────────────────────────────┘
```

---

## Complete Workflow

### Step 1: Build PE with Fabricator

```asm
; Call the fabricator
lea rbx, pe_buffer          ; Pre-allocated 64KB buffer
mov rcx, rbx
call Build_Full_PE          ; Returns RAX = PE file size

; Result: Valid PE geometry ready to write to disk
;   - DOS Header @ offset 0x00
;   - NT Headers @ offset 0x80
;   - Sections @ offset 0x120
;   - .text code @ offset 0x200
;   - .idata imports @ offset 0x400
```

### Step 2: Write PE to Disk (One-Time)

```asm
; CreateFileA → Write pe_buffer → CloseHandle
; Standard Windows file I/O
lea rcx, szFilename
mov edx, GENERIC_WRITE      ; 40000000h
; ... standard CreateFileA/WriteFile ...
```

### Step 3: Prepare Injector Code (Optional)

```asm
; If you want to hotpatch:
;   1. Allocate high-memory buffer
;   2. Emit your custom code
;   3. Use FF 25 bridge to connect

mov rcx, injection_buffer
call Emit_SUB_RSP_IMM8      ; 4 bytes: prologue

; ... your instruction emitters ...

add rcx, rax
call Emit_FunctionEpilogue_Reversed  ; 5 bytes: epilogue
```

### Step 4: Apply Bridge (Hotpatching)

```asm
; To hotpatch a running game function:
mov rcx, game_function_address      ; Where to patch
mov rdx, injection_buffer           ; Where to jump
call Emit_Absolute_Jump_Split       ; Writes FF 25 (14 bytes)

; The bridge now redirects:
;    game_function() → injection_buffer → epilogue → return
```

---

## API Reference

### Fabricator Functions

#### `Build_Full_PE`
**Purpose:** Complete PE32+ generation  
**Input:** `RCX` = buffer address (64KB recommended)  
**Output:** `EAX` = final PE file size  
**Guarantees:** Valid PE64 with all required sections  

```asm
lea rcx, pe_buffer
call Build_Full_PE
mov r12, rax               ; Save file size
; Now pe_buffer contains valid PE64
```

#### `Emit_DOS`
**Purpose:** Write DOS header  
**Input:** `RCX` = buffer address  
**Output:** Writes 64 bytes, `RAX` = undefined  

```asm
mov rcx, buffer
call Emit_DOS
; Buffer now has valid MZ header
```

#### `Emit_NT`
**Purpose:** Write NT headers + optional header + data directories  
**Input:** `RCX` = buffer @ offset 0x80, `DX` = section count  
**Output:** Writes ~240 bytes for PE32+  

```asm
lea rcx, [buffer + 80h]
mov dx, 3                  ; 3 sections: .text, .idata, .rdata
call Emit_NT
```

---

### Injector Functions

#### `Emit_Absolute_Jump_Split` (THE BRIDGE)
**Purpose:** Emit FF 25 absolute indirect jump (64-bit capable)  
**Input:** `RCX` = patch location, `RDX` = target address (64-bit)  
**Output:** `RAX` = 14 (bytes written), buffer modified  
**Opcode:** FF 25 00 00 00 00 [QWORD]  

```asm
mov rcx, 0x140001000       ; Patch original function
mov rdx, 0x7FFF0000       ; Jump to high memory
call Emit_Absolute_Jump_Split
; Now (0x140001000) → (0x7FFF0000) via FF 25 bridge
```

#### `Emit_Xor_Rdx_Rdx_Reversed`
**Purpose:** Emit XOR RDX, RDX (clear return value register)  
**Input:** `RCX` = buffer pointer  
**Output:** `RAX` = 3 (bytes written)  
**Opcode:** 48 31 D2  

```asm
lea rcx, [injection_buffer]
call Emit_Xor_Rdx_Rdx_Reversed
; Writes: 48 31 D2 (3 bytes)
```

#### `Emit_FunctionEpilogue_Reversed`
**Purpose:** Emit ADD RSP,28h + RET (stack cleanup + return)  
**Input:** `RCX` = buffer pointer  
**Output:** `RAX` = 5 (bytes written)  
**Opcode:** 48 83 C4 28 C3  
**Critical:** MUST match prologue displacement!  

```asm
lea rcx, [injection_buffer + 50h]
call Emit_FunctionEpilogue_Reversed
; Writes: 48 83 C4 28 C3 (5 bytes)
; Stack perfectly balanced if prologue was SUB RSP, 28h
```

---

### Resolver Functions

#### `Get_Kernel32_Base`
**Purpose:** Find kernel32.dll base address via PEB walk  
**Input:** None (uses GS register, Windows-only)  
**Output:** `RAX` = kernel32.dll base address  
**Guarantees:** No imports, no API calls, pure memory walk  

```asm
call Get_Kernel32_Base
; RAX now contains kernel32.dll base (e.g., 0x7FFF0000)
; Use this to resolve APIs by hash (CRC32)
```

---

### Generic Instruction Emitters

#### `Emit_SUB_RSP_IMM8`
Emit: `48 83 EC [imm8]` (SUB RSP, immediate byte)  
Input: `CL` = immediate, `RDI` = buffer  
Output: 4 bytes written  

#### `Emit_ADD_RSP_IMM8`
Emit: `48 83 C4 [imm8]` (ADD RSP, immediate byte)  
Input: `CL` = immediate, `RDI` = buffer  
Output: 4 bytes written  

#### `Emit_MOV_R64_IMM64`
Emit: `48 B8 [imm64]` (MOV RAX, 64-bit immediate)  
Input: `CL` = register, `RDX` = imm64, `RDI` = buffer  
Output: 10 bytes written  

#### `Emit_XOR_R64_R64`
Emit: `48 31` [ModR/M] (XOR r64, r64)  
Input: `CL` = dst reg, `DL` = src reg, `RDI` = buffer  
Output: 3 bytes written  

#### `Emit_CALL_RIP_INDIRECT`
Emit: `FF 15 [rel32]` (CALL [RIP + displacement])  
Input: `ECX` = rel32, `RDI` = buffer  
Output: 6 bytes written  

#### `Emit_LEA_RIP_R64`
Emit: `48 8D [ModR/M]` (LEA r64, [RIP + disp32])  
Input: `CL` = register, `EDX` = disp32, `RDI` = buffer  
Output: 7 bytes written  

#### `Emit_RET`
Emit: `C3` (RET)  
Input: `RDI` = buffer  
Output: 1 byte written  

---

## Practical Examples

### Example 1: Generate PE + Write to Disk

```asm
; PART A: Fabricate PE
lea rcx, pe_buffer
call Build_Full_PE
mov r8, rax                 ; File size = RAX

; PART B: Write to disk
lea rcx, [rel szFilename]   ; "output.exe"
mov edx, GENERIC_WRITE      ; 40000000h
xor r9, r9
mov dword ptr [rsp+20h], 2  ; CREATE_ALWAYS
call CreateFileA
mov rbx, rax                ; File handle

; PART C: Write data
mov rcx, rbx
lea rdx, pe_buffer
mov r8, r8                  ; File size (already in R8)
lea r9, [rsp+40h]           ; Bytes written
call WriteFile

; PART D: Cleanup
call CloseHandle
```

### Example 2: Hotpatch with FF 25 Bridge

```asm
; STEP 1: Get target function address
mov rcx, game_module_handle
mov rdx, 0x1234             ; RVA of function to patch
call get_function_va        ; Returns VA in RAX
mov r13, rax                ; Save target address

; STEP 2: Allocate high memory for injector
mov rcx, 0x1000             ; 4KB allocation
mov edx, MEM_COMMIT | MEM_RESERVE
mov r8d, PAGE_EXECUTE_READWRITE
call VirtualAlloc
mov r14, rax                ; Injection buffer

; STEP 3: Emit injector payload
mov rcx, r14
call Emit_SUB_RSP_IMM8      ; Prologue: 4 bytes
mov rcx, r14 + 4            ; Advance
call Emit_Xor_Rdx_Rdx_Reversed  ; Clear RDX: 3 bytes
mov rcx, r14 + 7            ; Advance
call Emit_FunctionEpilogue_Reversed  ; Epilogue: 5 bytes

; STEP 4: Apply bridge
mov rcx, r13                ; Original function address
mov rdx, r14                ; Injector buffer
call Emit_Absolute_Jump_Split       ; FF 25: 14 bytes

; Now any call to original function goes through injector!
```

### Example 3: Resolve kernel32 APIs (ZeroImport)

```asm
; STEP 1: Find kernel32 base
call Get_Kernel32_Base
mov r12, rax                ; kernel32.dll base

; STEP 2: To call APIs, you'd use CRC32 resolution
; (Requires Compute_CRC32_SSE42 + Resolve_Proc_Hash)
; Future integration: call with hash to get function pointer

; For now: kernel32 base is ready for manual export table walk
```

---

## Stack Discipline (Critical!)

### The Reversed Prologue-Epilogue Contract

```
ENTRY TO FUNCTION (RSP points to return address)
│
├─ SUB RSP, 0x28 (Prologue)
│  │ Allocates: 32 bytes shadow space + 8 bytes alignment
│  └─ RSP now 0x28 bytes lower
│
├─ [FUNCTION BODY]
│  │ Uses the allocated stack space
│  │ Must NOT mess with RSP offset
│  └─ If you allocate more, ADD to epilogue displacement!
│
├─ ADD RSP, 0x28 (Epilogue - MUST MATCH!)
│  │ Deallocates exactly 0x28 bytes
│  └─ RSP restored to point at return address
│
└─ RET (reads return address from RSP and jumps)
   Caller receives control with correct stack state
```

**If Epilogue Displacement Doesn't Match:**
```
Prologue: SUB RSP, 0x28    (allocate 40 bytes)
Epilogue: ADD RSP, 0x20    (deallocate 32 bytes) ← WRONG!

Result: RET reads 8 bytes BELOW return address
        Gets garbage → crash with segfault
```

---

## Sovereign Callsites

All exported functions are `public` and can be called from:
- Assembly code (direct `call` instructions)
- C/C++ via `extern "C"` declarations
- Other modules via PUBLIC linkage

```c
// Example: Calling from C++
extern "C" void Build_Full_PE();
extern "C" void Emit_Absolute_Jump_Split();

int main() {
    unsigned char buffer[65536] = {0};
    Build_Full_PE();                    // Generate PE
    // ... WriteFile to disk ...
    return 0;
}
```

---

## Debugging Tips

### Check Emission Correctness

```asm
; After each emitter call, verify bytes:
mov rcx, buffer
call Emit_SUB_RSP_IMM8
; Check buffer[0..3]:
;   buffer[0] = 48? (REX.W)
;   buffer[1] = 83? (opcode)
;   buffer[2] = EC? (RSP)
;   buffer[3] = 28? (immediate)
```

### Verify Bridge Works

```asm
; After FF 25 patch, test jump:
; Original  : mov rax, 1; ret
; After FF 25: FF 25 00 00 00 00 [target addr]; (old code)
;
; When called:
;   JMP [RIP+0] reads 8 bytes at RIP+6
;   Jumps to [target address]
;   Executes injected code
;   Prologue/epilogue handle stack
;   Returns to caller
```

### Trace PEB Walk

```asm
; After Get_Kernel32_Base:
mov rax, gs:[60h]
; RAX should be valid PEB address (Windows maintains this)
; If RAX = 0, something is severely wrong
```

---

## Performance Characteristics

| Operation | Bytes | Cycles | Notes |
|-----------|-------|--------|-------|
| Prologue (SUB RSP, 28h) | 4 | 1 | Allocate shadow space |
| Epilogue (ADD RSP, 28h + RET) | 5 | 2 | Deallocate + return |
| FF 25 bridge | 14 | 5-10 | Indirect jump (cache miss risk) |
| XOR RDX, RDX | 3 | 1 | Clear register (fast) |
| MOV R64, imm64 | 10 | 1 | 64-bit immediate (slow) |
| CALL [RIP+rel32] | 6 | 3-5 | Indirect call near |
| PE generation | - | - | One-time, negligible |

---

## Known Limitations & Workarounds

### ❌ Limitation: FF 25 is slower than E9
- **Why:** Indirect jump (must load address from memory)
- **When it matters:** Tight loops, recursive calls
- **Workaround:** Use E9 for nearby jumps (< 2GB), FF 25 for distance

### ❌ Limitation: Prologue/epilogue not optimized
- **Why:** 40 bytes shadow space required by x64 ABI
- **When it matters:** Leaf functions don't need shadow space
- **Workaround:** Manual optimization for leaf functions only

### ❌ Limitation: No exception handling (PDATA/XDATA)
- **Why:** Not yet implemented
- **When it matters:** Structured exception handling, debugging
- **Workaround:** Avoid exceptions in injected code

---

## What's Next

### Phase 2: CRC32 API Resolution
- [ ] Implement `Compute_CRC32_SSE42` (SSE 4.2 instruction)
- [ ] Implement `Resolve_Proc_Hash` (export directory walker)
- [ ] Precompute hashes for kernel32 APIs
- [ ] Integration example: hotpatch with API calls

### Phase 3: Complete Hotpatch Engine
- [ ] Process attachment (OpenProcess → PID)
- [ ] Memory protection bypass (VirtualProtect)
- [ ] Atomic patching (LOCK CMPXCHG16B or XCHG)
- [ ] Live injection into running games

### Phase 4: Advanced Features
- [ ] PDATA/XDATA generation (SEH support)  
- [ ] Relocation (.reloc) section generation (ASLR)
- [ ] Export directory generation (DLL support)
- [ ] Library archive (`.lib`) parsing

---

## References

- PE Format: https://en.wikipedia.org/wiki/Portable_Executable
- x64 ISA: https://www.felixcloutier.com/x86/
- PEB Structure: https://en.wikipedia.org/wiki/Process_Environment_Block
- Windows ABI: https://docs.microsoft.com/en-us/cpp/build/x64-software-conventions

---

**Document Version:** 1.0  
**Status:** ✅ Split Architecture Complete  
**Last Updated:** 2026-02-23  
**Audience:** Backend Designers, Reverse Engineers, PE Writers
