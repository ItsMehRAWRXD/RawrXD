# 🚨 CRITICAL: ABI VIOLATION DETECTED - DEPLOYMENT HALTED

## ⚠️ DO NOT DEPLOY TO PRODUCTION

**Status**: 🛑 **DEPLOYMENT HALTED**  
**Severity**: **CRITICAL**  
**Date**: 2026-07-07  
**Reason**: Potential ABI violation causing register/stack corruption  

---

## 🔍 Issue Summary

During final validation, **garbage timing values** were observed in the telemetry benchmark. This is **NOT a measurement error** - this is a **critical stability bug** indicating ABI (Application Binary Interface) violations in the MASM kernels.

### Root Cause Analysis

In assembly development, "garbage timing values" are almost never measurement errors. They are symptoms of:

1. **Non-Volatile Register Clobbering**: The assembly kernel is overwriting registers that the C++ compiler expects to be preserved (`rbx`, `rbp`, `rdi`, `rsi`, `r12`-`r15`), corrupting the host application's state.

2. **Stack Corruption**: The assembly kernel is not balancing the stack correctly (unmatched `push`/`pop` or failing to maintain 16-byte alignment), overwriting the return address or local variables in the benchmarking harness.

3. **Shadow Space Violations**: The assembly kernel is not respecting the 32-byte shadow space requirements when calling Win64 C++ functions.

### Why This Is Critical

**If deployed to production, this kernel will eventually cause:**
- Silent data corruption in the inference engine
- Random segmentation faults
- Intermittent crashes that are extremely difficult to debug
- Performance degradation under load
- Potential security vulnerabilities

---

## 🛠️ Immediate Action Required

### Step 1: Run ABI Integrity Test

A comprehensive **Register/ABI Integrity Wrapper** has been created to pinpoint exactly which register or stack pointer is causing the corruption.

**Build and run the test:**

```bash
cd d:\rawrxd-ci-bootstrap\build-ninja
ninja abi_integrity_test
.\src\validation\abi_integrity_test.exe
```

**What the test does:**
1. Saves ALL registers (RAX-R15, YMM0-YMM15) before calling the MASM kernel
2. Calls the MASM kernel with test data
3. Compares ALL registers after the call
4. Reports any ABI violations (non-volatile register corruption)
5. Validates functional correctness

### Step 2: Fix ABI Violations

Based on the test results, fix the identified issues:

#### Common ABI Violations and Fixes

**Non-Volatile Register Clobbering:**
```asm
; ❌ WRONG: Clobbering RBX without saving it
MASM_Kernel PROC
    mov rbx, rcx          ; RBX is non-volatile!
    ; ... kernel code ...
    ret
MASM_Kernel ENDP

; ✅ CORRECT: Save and restore RBX
MASM_Kernel PROC FRAME
    push rbx              ; Save RBX
    .pushreg rbx
    ; ... kernel code ...
    pop rbx               ; Restore RBX
    ret
MASM_Kernel ENDP
```

**Stack Alignment Issues:**
```asm
; ❌ WRONG: Stack not 16-byte aligned
MASM_Kernel PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 32           ; Shadow space, but stack might be misaligned
    .allocstack 32
    .endprolog
    ; ... kernel code ...
    add rsp, 32
    pop rbp
    ret
MASM_Kernel ENDP

; ✅ CORRECT: Ensure 16-byte stack alignment
MASM_Kernel PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 48           ; 32 shadow + 16 for alignment
    .allocstack 48
    .endprolog
    ; ... kernel code ...
    add rsp, 48
    pop rbp
    ret
MASM_Kernel ENDP
```

**Shadow Space Violations:**
```asm
; ❌ WRONG: Calling C++ function without shadow space
MASM_Kernel PROC
    ; ... kernel code ...
    call SomeCppFunction   ; No shadow space allocated!
    ; ... kernel code ...
    ret
MASM_Kernel ENDP

; ✅ CORRECT: Allocate shadow space before calling C++
MASM_Kernel PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 32           ; Shadow space for C++ calls
    .allocstack 32
    .endprolog
    ; ... kernel code ...
    call SomeCppFunction   ; Now safe to call C++
    ; ... kernel code ...
    add rsp, 32
    pop rbp
    ret
MASM_Kernel ENDP
```

### Step 3: Re-Test After Fixes

After fixing the ABI violations:

1. **Rebuild the MASM kernels:**
   ```bash
   cd d:\rawrxd-ci-bootstrap\build-ninja
   ninja telemetry_masm_kernels
   ```

2. **Run ABI integrity test again:**
   ```bash
   .\src\validation\abi_integrity_test.exe
   ```

3. **Verify all tests pass:**
   - ✅ Functional correctness: PASS
   - ✅ ABI compliance: PASS

4. **Run telemetry validation:**
   ```bash
   .\src\validation\telemetry_validation.exe
   ```

5. **Verify timing values are reasonable:**
   - Cycle counts should be consistent and within expected ranges
   - No negative or extremely large values
   - No random fluctuations between runs

---

## 📋 ABI Compliance Checklist

Before deploying ANY MASM kernel to production, verify:

### Non-Volatile Registers (MUST be preserved)
- [ ] **RBX** - Saved and restored if modified
- [ ] **RBP** - Saved and restored if modified
- [ ] **RDI** - Saved and restored if modified
- [ ] **RSI** - Saved and restored if modified
- [ ] **R12** - Saved and restored if modified
- [ ] **R13** - Saved and restored if modified
- [ ] **R14** - Saved and restored if modified
- [ ] **R15** - Saved and restored if modified

### Stack Management
- [ ] **Stack alignment** - RSP is 16-byte aligned before `call` instructions
- [ ] **Shadow space** - 32 bytes allocated before calling C++ functions
- [ ] **Push/pop balance** - Every `push` has a matching `pop`
- [ ] **Frame pointers** - Properly set up with `.pushreg`, `.setframe`, `.allocstack`

### Volatile Registers (CAN be modified)
- **RAX, RCX, RDX, R8-R11** - Caller-saved, can be modified freely
- **XMM0-XMM5 (YMM0-YMM5)** - Caller-saved, can be modified freely
- **XMM6-XMM15 (YMM6-YMM15)** - Must be preserved in Windows x64 ABI

### Function Prologue/Epilogue
- [ ] **Prologue** - Uses `PROC FRAME` directive with proper directives
- [ ] **Epilogue** - Properly restores stack and registers before `ret`

---

## 🎯 Expected Test Results

### ABI Integrity Test Output (PASS)

```
========================================
RawrXD MASM Kernel ABI Integrity Test
========================================

=== CPU Feature Check ===
CPUID Leaf 0: ...
AVX: Yes

Test data: 1024 floats from -4.0 to 4.0
Alignment: 0 bytes

=== Functional Correctness Test (SiLU) ===
✅ PASS: All values correct (max error: 2.6e-06)

=== ABI Compliance Test (SiLU) ===
=== ABI Integrity Test for MASM_Silu_Activation_AVX512 ===
Data pointer: 0x... (alignment: 0)
Data size: 4096 bytes
✅ ABI COMPLIANT: All non-volatile registers preserved
ASM function return value: 0
========================================

✅ PASS: ABI compliant (all non-volatile registers preserved)

========================================
=== FINAL RESULT ===
========================================
✅ ALL TESTS PASSED
   - Functional correctness: PASS
   - ABI compliance: PASS

🎉 MASM kernel is PRODUCTION READY!
```

### ABI Integrity Test Output (FAIL)

```
========================================
RawrXD MASM Kernel ABI Integrity Test
========================================

=== CPU Feature Check ===
CPUID Leaf 0: ...
AVX: Yes

Test data: 1024 floats from -4.0 to 4.0
Alignment: 0 bytes

=== Functional Correctness Test (SiLU) ===
✅ PASS: All values correct (max error: 2.6e-06)

=== ABI Compliance Test (SiLU) ===
=== ABI Integrity Test for MASM_Silu_Activation_AVX512 ===
Data pointer: 0x... (alignment: 0)
Data size: 4096 bytes
❌ FAIL: Register RBX corrupted: 0x0000000000000000 -> 0x0000000000000001
❌ FAIL: Register R12 corrupted: 0x0000000000000000 -> 0x0000000000000002
❌ FAIL: ABI VIOLATION: Non-volatile registers corrupted!
ASM function return value: 0
========================================

❌ FAIL: ABI violations detected (see above for details)

========================================
=== FINAL RESULT ===
========================================
❌ TESTS FAILED
   - Functional correctness: PASS
   - ABI compliance: FAIL

⚠️  DO NOT DEPLOY - Fix issues before production!
```

---

## 📚 References

### x64 Calling Convention (Microsoft)
- [Microsoft x64 Calling Convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [Register Usage](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention#register-usage)
- [Stack Alignment](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention#stack-allocation)

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

## 🚨 CRITICAL REMINDER

**DO NOT DEPLOY TO PRODUCTION UNTIL:**

1. ✅ ABI integrity test passes with no violations
2. ✅ Functional correctness test passes
3. ✅ Timing values are consistent and reasonable
4. ✅ All non-volatile registers are preserved
5. ✅ Stack alignment is correct
6. ✅ Shadow space is properly allocated

**The debugging heuristic:**

> "If the timing values look like garbage, the kernel is corrupting the ABI. 
> Fix the ABI violations BEFORE optimizing performance."

---

## 📞 Next Steps

1. **Run the ABI integrity test** to identify the exact violation
2. **Fix the identified issues** in the MASM kernel
3. **Re-test** until all tests pass
4. **Update documentation** with lessons learned
5. **Proceed to production deployment** only after all tests pass

**Status**: 🛑 **DEPLOYMENT HALTED UNTIL ABI VIOLATIONS ARE FIXED**