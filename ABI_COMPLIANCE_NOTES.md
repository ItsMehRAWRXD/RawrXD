# ABI Compliance Notes - RawrXD Kernel Integration

## 🛡️ Critical ABI Compliance Requirements

This document captures the critical ABI compliance requirements discovered during the YMM register preservation bug fix.

---

## ⚠️ Windows x64 ABI Requirements

### Non-Volatile Registers (MUST be preserved)

| Register Type | Volatile (Caller-Saved) | Non-Volatile (Callee-Saved) |
|---------------|------------------------|----------------------------|
| **General Purpose** | RAX, RCX, RDX, R8-R11 | RBX, RBP, RDI, RSI, RSP, R12-R15 |
| **Vector (XMM/YMM)** | XMM0-XMM5 (YMM0-YMM5) | **XMM6-XMM15 (YMM6-YMM15)** |

### Critical Finding

**YMM6-YMM15 are NON-VOLATILE in Windows x64 ABI!**

The original MASM kernel incorrectly assumed all YMM registers were volatile, leading to silent data corruption.

---

## 🐛 Bug Discovery

### Symptoms
- **Garbage timing values**: NaN, 9.22e+18, zero cycles
- **Silent data corruption**: C++ timing code using YMM registers corrupted
- **Intermittent failures**: Unpredictable behavior in production

### Root Cause
MASM kernel clobbered YMM6-YMM15 without saving/restoring them, violating Windows x64 ABI.

### Fix
Added proper save/restore of YMM6-YMM15 in prologue/epilogue:

```asm
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
```

---

## 📋 ABI Compliance Checklist

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

## 🧪 Testing Requirements

### Mandatory Tests Before Deployment

1. **ABI Integrity Test**: Verify all non-volatile registers are preserved
2. **Zero-Assembly Test**: Isolate timing wrapper from assembly kernel
3. **Telemetry Validation**: Verify timing values are stable and reasonable
4. **Functional Correctness**: Verify mathematical accuracy

### Test Commands

```bash
# Build and run ABI integrity test
ninja abi_integrity_test
.\bin\abi_integrity_test.exe

# Build and run zero-assembly test
ninja zero_assembly_test
.\bin\zero_assembly_test.exe

# Build and run telemetry validation
ninja telemetry_validation
.\bin\telemetry_validation.exe
```

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

---

## 🎓 Lessons Learned

1. **"Garbage Data" is Never a Measurement Error**: Always investigate root cause
2. **The Diagnostic Gap**: ABI tests must check ALL aspects (registers, stack, alignment)
3. **Zero-Assembly Test is Critical**: Isolates timing wrapper from assembly kernel
4. **Windows x64 ABI is Complex**: Always consult official documentation

---

**Date**: 2026-07-07  
**Status**: ✅ **PRODUCTION READY**  
**Severity**: **CRITICAL** - Would cause silent data corruption  
**Root Cause**: YMM register preservation violation  
**Fix**: Proper save/restore of non-volatile YMM6-YMM15 registers