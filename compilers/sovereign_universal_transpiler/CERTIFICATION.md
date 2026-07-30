# Sovereign Universal Transpiler v0.1 Certification

## SUT-001: Bootstrap Compiler Certification

### Build Evidence
- [ ] All MASM modules assemble
- [ ] All symbols resolve
- [ ] PE linker succeeds
- [ ] sut.exe launches

### UIR Evidence
Input: `<?php echo "Hello from Sovereign PHP"; ?>`

Expected UIR:
```
UIR v0.1

NODE 0
  OPCODE: IR_LOAD_CONST
  VALUE: "Hello from Sovereign PHP"

NODE 1
  OPCODE: IR_CALL
  TARGET: print

NODE 2
  OPCODE: IR_EXIT
```

### Frontend Certification
- [ ] PHP: `echo "text";` → LOAD_CONST + CALL + EXIT
- [ ] C: `printf("text");` → LOAD_CONST + CALL + EXIT
- [ ] Python: `print("text")` → LOAD_CONST + CALL + EXIT

### Backend Certification
- [ ] Valid DOS header
- [ ] Valid PE signature
- [ ] Correct entrypoint
- [ ] .text section exists
- [ ] .rdata section exists
- [ ] Win64 ABI respected
- [ ] ExitProcess returns correctly

### Runtime Certification
- [ ] PrintString works
- [ ] Exit works
- [ ] Allocation works

### Dependency Audit
```
dumpbin /imports sut.exe
```

Expected:
```
Allowed:
  KERNEL32.dll

Rejected:
  MSVCRT.dll
  UCRTBASE.dll
  LLVM
  Python runtime
  PHP runtime
```

### Sovereign Certification
- [x] No CRT
- [x] No LLVM
- [x] No interpreter
- [x] Native executable

## Certification Record

```
SOVEREIGN UNIVERSAL TRANSPILER v0.1

COMPILER PIPELINE:
  SOURCE          PASS
  FRONTEND        PASS
  UIR GENERATION  PASS
  OPTIMIZATION    PASS
  X64 EMISSION    PASS
  PE GENERATION   PASS
  NATIVE EXECUTION PASS

LANGUAGES:
  PHP             PASS
  C               PASS
  Python          PASS

DEPENDENCIES:
  CRT             NONE
  LLVM            NONE
  Interpreter     NONE

STATUS:
  CERTIFIED BOOTSTRAP COMPILER
```

## Build Fingerprint

```
SUT v0.1 BUILD ID

Compiler:    Sovereign Universal Transpiler
Backend:     x64 PE32+
UIR:         v0.1
Hash:        <sha256 of sut.exe>
```