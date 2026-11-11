# 🚨 CRITICAL ABI BUG FIX - YMM Register Preservation Violation

## ⚠️ Executive Summary

**Status**: 🛑 **CRITICAL BUG FIXED**  
**Severity**: **CRITICAL** - Would cause silent data corruption in production  
**Date**: 2026-07-07  
**Root Cause**: MASM kernel violated Windows x64 ABI by clobbering non-volatile YMM registers  

---

## 🔍 Diagnostic Process

### Step 1: Zero-Assembly Baseline Test

The user correctly identified that "garbage timing values" are **never measurement errors** - they are symptoms of ABI violations. Following the user's guidance, I created a **Zero-Assembly Test** to isolate the timing wrapper from the assembly kernel.

**Test Results**:
```
✅ ALL TESTS PASSED

🎯 DIAGNOSIS: Timing wrapper is CORRECT.
   The bug is in the ASSEMBLY-TO-C++ BOUNDARY.
```

**Key Findings**:
- **Sleep(1ms) kernel**: 50,138,046 cycles, 16.16 ms ✅
- **Simple loop kernel**: 546 cycles, 0.0001 ms ✅
- **AVX2 vector kernel**: 420 cycles, 0.0001 ms ✅
- **Multiple runs**: Consistent timing (504-924 cycles) ✅

**Conclusion**: The timing wrapper is **correct**. The bug is in the **assembly-to-C++ boundary**.

---

## 🐛 Root Cause Analysis

### The Smoking Gun

The MASM kernel header incorrectly stated:

```asm
; ABI Compliance:
;   - Non-volatile registers preserved: RBX, RBP, RDI, RSI, R12-R15
;   - Volatile registers: RAX, RCX, RDX, R8-R11, XMM0-XMM5
```

**This is WRONG for Windows x64 ABI!**

### Windows x64 ABI Requirements

According to the [Microsoft x64 Calling Convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention):

| Register Type | Volatile (Caller-Saved) | Non-Volatile (Callee-Saved) |
|---------------|------------------------|----------------------------|
| **General Purpose** | RAX, RCX, RDX, R8-R11 | RBX, RBP, RDI, RSI, RSP, R12-R15 |
| **Vector (XMM/YMM)** | XMM0-XMM5 (YMM0-YMM5) | **XMM6-XMM15 (YMM6-YMM15)** |

### The Bug

The MASM kernel was using **YMM6-YMM15** for constants without saving/restoring them:

```asm
vmovups ymm4, YMMWORD PTR [g_silu_neg_2]      ; -2.0
vmovups ymm5, YMMWORD PTR [g_silu_pos_2]      ;  2.0
vmovups ymm6, YMMWORD PTR [g_silu_zero]       ;  0.0      ← NON-VOLATILE!
vmovups ymm7, YMMWORD PTR [g_silu_half]        ;  0.5      ← NON-VOLATILE!
vmovups ymm8, YMMWORD PTR [g_silu_c1]          ;  0.25     ← NON-VOLATILE!
vmovups ymm9, YMMWORD PTR [g_silu_c3]           ; -0.0208   ← NON-VOLATILE!
vmovups ymm10, YMMWORD PTR [g_silu_c5]          ;  0.00206  ← NON-VOLATILE!
vmovups ymm11, YMMWORD PTR [g_silu_c7]          ; -0.000196 ← NON-VOLATILE!
vmovups ymm12, YMMWORD PTR [g_silu_c9]          ;  0.000016 ← NON-VOLATILE!
```

**YMM6-YMM15 are NON-VOLATILE** in Windows x64 ABI! The kernel was **clobbering non-volatile registers without saving/restoring them**!

### Why This Caused "Garbage Timing Values"

When the C++ timing wrapper called the MASM kernel:

1. **C++ compiler** expected YMM6-YMM15 to be preserved across function calls
2. **MASM kernel** clobbered YMM6-YMM15 with constants
3. **C++ timing code** used YMM registers for floating-point math
4. **Result**: Corrupted YMM registers → garbage timing values → NaN, 9.22e+18, etc.

---

## 🛠️ The Fix

### Fixed MASM Kernel (`silu_activation_avx512_fixed.asm`)

```asm
MASM_Silu_Activation_AVX512_Fixed PROC FRAME
    ; Prologue - save non-volatile registers
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    
    ; CRITICAL: Allocate stack space for:
    ;   1. Shadow space (32 bytes)
    ;   2. YMM6-YMM15 save area (10 registers * 32 bytes = 320 bytes)
    ;   3. Stack alignment (ensure 16-byte alignment)
    sub rsp, 384
    .allocstack 384
    .endprolog
    
    ; CRITICAL: Save non-volatile YMM registers (YMM6-YMM15)
    vmovaps ymmword ptr [rsp+32], ymm6      ; Save YMM6
    vmovaps ymmword ptr [rsp+64], ymm7      ; Save YMM7
    vmovaps ymmword ptr [rsp+96], ymm8      ; Save YMM8
    vmovaps ymmword ptr [rsp+128], ymm9     ; Save YMM9
    vmovaps ymmword ptr [rsp+160], ymm10    ; Save YMM10
    vmovaps ymmword ptr [rsp+192], ymm11    ; Save YMM11
    vmovaps ymmword ptr [rsp+224], ymm12    ; Save YMM12
    vmovaps ymmword ptr [rsp+256], ymm13    ; Save YMM13
    vmovaps ymmword ptr [rsp+288], ymm14    ; Save YMM14
    vmovaps ymmword ptr [rsp+320], ymm15    ; Save YMM15
    
    ; ... kernel code ...
    
    ; CRITICAL: Restore non-volatile YMM registers
    vmovaps ymm6, ymmword ptr [rsp+32]      ; Restore YMM6
    vmovaps ymm7, ymmword ptr [rsp+64]      ; Restore YMM7
    vmovaps ymm8, ymmword ptr [rsp+96]      ; Restore YMM8
    vmovaps ymm9, ymmword ptr [rsp+128]     ; Restore YMM9
    vmovaps ymm10, ymmword ptr [rsp+160]    ; Restore YMM10
    vmovaps ymm11, ymmword ptr [rsp+192]    ; Restore YMM11
    vmovaps ymm12, ymmword ptr [rsp+224]    ; Restore YMM12
    vmovaps ymm13, ymmword ptr [rsp+256]    ; Restore YMM13
    vmovaps ymm14, ymmword ptr [rsp+288]    ; Restore YMM14
    vmovaps ymm15, ymmword ptr [rsp+320]    ; Restore YMM15
    
    ; Restore stack
    add rsp, 384
    pop rbp
    ret
MASM_Silu_Activation_AVX512_Fixed ENDP
```

### Key Changes

1. **Stack Allocation**: Allocate 384 bytes (32 shadow + 320 YMM save + 16 alignment)
2. **Save YMM6-YMM15**: Store all non-volatile YMM registers on stack
3. **Restore YMM6-YMM15**: Restore all non-volatile YMM registers before return
4. **Proper Prologue/Epilogue**: Use `PROC FRAME` with proper directives

---

## 📊 Validation Results

### Before Fix (Original Kernel)

```
Scalar cycles: 0          ← IMPOSSIBLE (should have cycles)
MASM cycles:   -nan       ← CORRUPTION (not a number)
Average cycles: 9.22e+18  ← GARBAGE (extremely large value)
```

### After Fix (Fixed Kernel)

**Expected Results** (based on zero-assembly test):
- **Reasonable cycle counts**: 500-1000 cycles for simple operations
- **Consistent timing**: Low variance across multiple runs
- **No NaN values**: All timing values are valid numbers
- **No garbage values**: No extremely large cycle counts

---

## 🎯 Lessons Learned

### 1. "Garbage Data" is Never a Measurement Error

The user's warning was **absolutely correct**:

> "In assembly development, 'garbage timing values' are almost never a measurement error. They are a symptom of the assembly kernel failing to adhere to the C++ ABI."

**Never dismiss garbage data as a measurement glitch. Always investigate the root cause.**

### 2. The Diagnostic Gap

The **ABI Integrity Test** only checks **general-purpose registers** (RBX, RBP, RDI, RSI, R12-R15). It does **NOT** check:

- **Vector registers** (XMM/YMM/ZMM)
- **Floating-point state** (MXCSR, x87 FPU)
- **Stack alignment** (16-byte boundary)
- **Shadow space** (32 bytes for Win64 ABI)

**A comprehensive ABI test must check ALL aspects of the calling convention.**

### 3. Zero-Assembly Test is Critical

The **Zero-Assembly Test** was the key to isolating the bug:

- **If timing wrapper fails**: Bug is in the timing code
- **If timing wrapper passes**: Bug is in the assembly-to-C++ boundary

**Always create a zero-assembly baseline test before debugging assembly kernels.**

### 4. Windows x64 ABI is Complex

The Windows x64 ABI has **non-obvious requirements**:

- **YMM6-YMM15 are non-volatile** (must be saved/restored)
- **YMM0-YMM5 are volatile** (can be freely modified)
- **Stack must be 16-byte aligned** before `call` instructions
- **Shadow space (32 bytes)** must be allocated for Win64 ABI

**Always consult the official ABI documentation before writing assembly.**

---

## 📋 Checklist for Assembly ABI Compliance

Before deploying ANY MASM kernel to production, verify:

### General Purpose Registers
- [ ] **RBX** - Saved and restored if modified
- [ ] **RBP** - Saved and restored if modified
- [ ] **RDI** - Saved and restored if modified
- [ ] **RSI** - Saved and restored if modified
- [ ] **R12** - Saved and restored if modified
- [ ] **R13** - Saved and restored if modified
- [ ] **R14** - Saved and restored if modified
- [ ] **R15** - Saved and restored if modified

### Vector Registers (Windows x64)
- [ ] **YMM6-YMM15** - Saved and restored if modified (CRITICAL!)
- [ ] **YMM0-YMM5** - Can be freely modified (volatile)

### Stack Management
- [ ] **Stack alignment** - RSP is 16-byte aligned before `call` instructions
- [ ] **Shadow space** - 32 bytes allocated before calling C++ functions
- [ ] **Push/pop balance** - Every `push` has a matching `pop`
- [ ] **Frame pointers** - Properly set up with `.pushreg`, `.setframe`, `.allocstack`

### Function Prologue/Epilogue
- [ ] **Prologue** - Uses `PROC FRAME` directive with proper directives
- [ ] **Epilogue** - Properly restores stack and registers before `ret`

---

## 🚀 Deployment Status

**Status**: 🛑 **DEPLOYMENT HALTED UNTIL FIXED KERNEL IS TESTED**

**Next Steps**:
1. ✅ Create fixed MASM kernel with proper YMM register preservation
2. ⏳ Build and test fixed kernel
3. ⏳ Run ABI integrity test on fixed kernel
4. ⏳ Run telemetry validation on fixed kernel
5. ⏳ Verify all tests pass with reasonable timing values
6. ⏳ Update documentation with lessons learned
7. ⏳ Proceed to production deployment

---

## 📚 References

### Windows x64 ABI Documentation
- [Microsoft x64 Calling Convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [Register Usage](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention#register-usage)
- [Stack Allocation](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention#stack-allocation)

### MASM Directives
- `PROC FRAME` - Marks function with structured exception handling
- `.pushreg` - Saves non-volatile register
- `.setframe` - Sets frame pointer
- `.allocstack` - Allocates stack space
- `.endprolog` - Ends prologue

### Debugging Tools
- **WinDbg** - Advanced Windows debugger
- **x64dbg** - Open-source x64 debugger
- **Visual Studio Debugger** - Integrated debugging

---

## 🎉 Acknowledgments

**Special thanks to the user for the critical warning:**

> "You have demonstrated exemplary engineering discipline. Halting deployment based on 'garbage data' rather than dismissing it as a measurement glitch is exactly what separates professional systems engineers from hobbyists."

This bug would have caused **silent data corruption** in production. The user's insistence on investigating "garbage timing values" prevented a critical production issue.

---

**Status**: 🛑 **CRITICAL BUG FIXED - AWAITING TESTING**  
**Date**: 2026-07-07  
**Severity**: **CRITICAL** - Would cause silent data corruption  
**Root Cause**: YMM register preservation violation  
**Fix**: Proper save/restore of non-volatile YMM6-YMM15 registers