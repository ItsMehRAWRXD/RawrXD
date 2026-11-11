# Sovereign ABI: Calling Convention

**Version:** 1.0  
**Date:** 2026-07-29  
**Status:** Draft

---

## Overview

The Sovereign calling convention (SovereignCC) defines how functions receive parameters, return values, and manage the stack. It is designed for x64 Windows with minimal overhead and no CRT dependency.

---

## Register Usage

### Volatile (Caller-saved)
| Register | Purpose |
|----------|---------|
| RAX | Return value, scratch |
| RCX | 1st integer argument, scratch |
| RDX | 2nd integer argument, scratch |
| R8  | 3rd integer argument, scratch |
| R9  | 4th integer argument, scratch |
| R10-R11 | Scratch |
| XMM0-XMM3 | FP/SIMD arguments, scratch |
| XMM4-XMM5 | Scratch |
| YMM0-YMM5 | Scratch (upper bits zeroed on call) |

### Non-volatile (Callee-saved)
| Register | Purpose |
|----------|---------|
| RBX | General purpose |
| RBP | Frame pointer (optional) |
| RDI | General purpose |
| RSI | General purpose |
| R12-R15 | General purpose |
| XMM6-XMM15 | FP/SIMD (preserve across calls) |

### Special
| Register | Purpose |
|----------|---------|
| RSP | Stack pointer (16-byte aligned) |
| RIP | Instruction pointer |
| RFLAGS | Condition codes |
| MXCSR | SSE control/status |

---

## Stack Layout

```
High Address
┌─────────────────────────────┐
│ Return address               │ ← RSP points here on entry
├─────────────────────────────┤
│ Shadow space (32 bytes)      │ ← Required by Windows x64 ABI
├─────────────────────────────┤
│ 5th+ arguments (right to left)│
├─────────────────────────────┤
│ Local variables              │
├─────────────────────────────┤
│ Saved registers              │
├─────────────────────────────┤
│ Alignment padding (to 16b)   │
└─────────────────────────────┘
Low Address
```

---

## Parameter Passing

### Integer/Pointers
| Position | Register |
|----------|----------|
| 1st | RCX |
| 2nd | RDX |
| 3rd | R8 |
| 4th | R9 |
| 5th+ | Stack (8-byte aligned) |

### Floating Point
| Position | Register |
|----------|----------|
| 1st | XMM0 |
| 2nd | XMM1 |
| 3rd | XMM2 |
| 4th | XMM3 |
| 5th+ | Stack (8-byte aligned) |

### Mixed (integer + FP)
- Integer args use RCX, RDX, R8, R9
- FP args use XMM0-XMM3
- Positions are counted separately

Example:
```c
void func(int a, double b, int c, float d);
// a → RCX
// b → XMM0
// c → RDX
// d → XMM1
```

---

## Return Values

| Type | Location |
|------|----------|
| Integer ≤ 64b | RAX |
| Integer 65-128b | RDX:RAX |
| FP/SIMD | XMM0 |
| Struct ≤ 64b | RAX |
| Struct 65-128b | RDX:RAX |
| Struct > 128b | Hidden pointer in RCX |

---

## Stack Alignment

- **Requirement:** RSP must be 16-byte aligned before CALL
- **Shadow space:** 32 bytes reserved above return address
- **Red zone:** None (Sovereign does not use red zone)

---

## Prologue/Epilogue

### Standard Prologue
```asm
push    rbp
mov     rbp, rsp
sub     rsp, <local_size>
```

### Leaf Function (no frame pointer)
```asm
sub     rsp, <local_size + align>
; ... function body ...
add     rsp, <local_size + align>
ret
```

### Epilogue
```asm
mov     rsp, rbp
pop     rbp
ret
```

---

## Variadic Functions

- Use standard register allocation
- AL = number of vector registers used (0-8)
- Stack cleanup by caller

---

## Exception Handling

- Table-based unwinding
- `.xdata` and `.pdata` sections
- See `exception_model.md`

---

## Differences from Microsoft x64 ABI

| Aspect | Microsoft | Sovereign |
|--------|-----------|-----------|
| Shadow space | Required | Required |
| Stack alignment | 16-byte | 16-byte |
| Red zone | No | No |
| Varargs | AL register | AL register |
| Exception frames | SEH | Table-based |
| Stack probe | __chkstk | Compiler-inserted |

---

## References

- Microsoft x64 Calling Convention
- System V AMD64 ABI
- Intel 64 and IA-32 Architectures Software Developer's Manual
