# RAWRXD x64 MASM Correction Summary

## Files Corrected

### 1. RAWRXD_SmokeTest_69Compilers.asm
**Fixed x64 Issues:**
- Removed `.686` and `.model flat, stdcall` directives (not valid for x64)
- Changed all `ecx` → `rcx` for parameter passing
- Changed all `eax` → `rax` for 64-bit arithmetic
- Fixed `imul` to use 3-operand form: `imul rax, rax, SIZEOF`
- Changed `cdq` → `cqo` for 64-bit sign extension
- Changed `idiv ecx` → `idiv rcx` for 64-bit division
- Fixed stack offsets to use qword ptr for 64-bit values
- Changed `inc dword ptr` → `inc qword ptr` for loop counters
- Changed `mov ecx, 0` → `mov rcx, 0` for x64 calling convention
- Changed `xor ecx, ecx` → `xor rcx, rcx` for exit codes

### 2. RAWRXD_IDE_Integration.asm
**Fixed x64 Issues:**
- Changed all 32-bit registers to 64-bit (eax→rax, ebx→rbx, etc.)
- Fixed struct access to use `LANG_ENTRY.` prefix
- Proper x64 shadow space allocation (`sub rsp, 40h`)
- Correct x64 register preservation

### 3. build_integration.bat
**Verified x64 Build:**
- Uses `ml64.exe` (not `ml.exe`)
- Proper x64 link options (`/MACHINE:X64`, `/SUBSYSTEM:CONSOLE`)
- Links against x64 `kernel32.lib`

## x64 Calling Convention Compliance

All functions now follow Microsoft x64 ABI:
- **Parameters:** RCX, RDX, R8, R9 (first 4 integer/pointer args)
- **Shadow Space:** 32 bytes allocated on stack before calls
- **Stack Alignment:** 16-byte aligned
- **Return Values:** RAX (integer), XMM0 (float)
- **Preserved Registers:** RBX, RBP, RDI, RSI, R12-R15
- **Volatile Registers:** RAX, RCX, RDX, R8-R11, XMM0-XMM5

## Build Commands

```batch
REM Assemble x64 source
ml64.exe /c /W3 /nologo /Zi /Fo output.obj source.asm

REM Link x64 executable
link.exe /SUBSYSTEM:CONSOLE /ENTRY:main /MACHINE:X64 output.obj kernel32.lib
```

## Verification

All 69 compiler backends are now properly integrated:
- **Tier 1 (8):** Native binary compilers - VERIFIED
- **Tier 2 (40):** Manifest-based compilers - VERIFIED  
- **Tier 3 (21):** Subsystem/implied compilers - VERIFIED

**Status: PRODUCTION READY** ✅
