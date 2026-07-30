# Sovereign Universal Transpiler (SUT) v0.1

**A bootstrap compiler that converts PHP/C/Python source into native Windows PE32+ executables with zero external dependencies.**

## Architecture

```
SOURCE
  |
  +----------+-----------+
  |          |           |
 PHP        C        Python
  |          |           |
  v          v           v
       FRONTEND ABI
             |
             v
    +----------------+
    |      UIR       |    (Universal IR - 5 opcodes)
    | immutable ABI  |
    +----------------+
             |
             v
    +----------------+
    | Optimizer      |    (constant fold, dead removal)
    +----------------+
             |
             v
    +----------------+
    | x64 Emitter    |    (Win64 ABI)
    +----------------+
             |
             v
    +----------------+
    | PE32+ Writer   |    (zero dependencies)
    +----------------+
             |
             v
        native.exe
```

## UIR v0.1 - Universal IR

The stable contract between frontends and backend:

```asm
UIR_NODE STRUCT
    opcode      DWORD ?
    flags       DWORD ?
    operand0    QWORD ?
    operand1    QWORD ?
    operand2    QWORD ?
UIR_NODE ENDS
```

**Opcodes:**
| Opcode | Value | Description |
|--------|-------|-------------|
| IR_NOP | 0 | No operation |
| IR_LOAD_CONST | 1 | Load constant (string/number) |
| IR_CALL | 2 | Call runtime function |
| IR_RETURN | 3 | Return from function |
| IR_EXIT | 4 | Exit process |

## Frontend ABI

Every language adapter implements:

```asm
; RCX = source buffer
; RDX = source size
; R8  = UIR output buffer
; Returns: RAX = UIR node count
FrontendCompile PROC
    ret
FrontendCompile ENDP
```

## Project Layout

```
SOVEREIGN_UNIVERSAL_TRANSPILER/
├── kernel/
│   ├── compiler.asm       # Orchestration
│   ├── lexer.asm          # Shared tokenizer
│   ├── token.asm          # Token definitions
│   ├── uir.asm            # Universal IR
│   ├── optimizer.asm      # IR optimization
│   ├── emitter_x64.asm    # x64 code generation
│   ├── pe_writer.asm      # PE32+ writer
│   ├── diagnostics.asm    # Error reporting
│   └── utils.asm          # Common helpers
├── frontends/
│   ├── frontend_api.asm   # ABI contract
│   ├── php_adapter.asm    # PHP frontend
│   ├── c_adapter.asm      # C frontend
│   └── python_adapter.asm # Python frontend
├── runtime/
│   ├── runtime.asm        # Runtime registration
│   ├── print.asm          # Console output
│   ├── exit.asm           # Process termination
│   └── memory.asm         # Memory allocation
├── tests/
│   ├── echo.php           # PHP test
│   ├── hello.c            # C test
│   ├── hello.py           # Python test
│   └── expected/
│       └── hello.txt      # Expected output
└── build.bat              # Bootstrap build
```

## Build

```batch
cd SOVEREIGN_UNIVERSAL_TRANSPILER
build.bat
```

Output: `build\sut.exe`

## Usage

```batch
sut.exe tests\echo.php echo.exe
echo.exe
```

Expected output:
```
Hello from Sovereign PHP
```

## Supported Syntax (v0.1)

### PHP
```php
<?php
echo "Hello from Sovereign PHP";
?>
```

### C
```c
printf("Hello from Sovereign C");
```

### Python
```python
print("Hello from Sovereign Python")
```

All three generate the same UIR:
```
LOAD_CONST "Hello..."
CALL print
EXIT
```

## Certification Checkpoints

| Checkpoint | Description | Status |
|------------|-------------|--------|
| UIR-001 | IR node creation | ✅ |
| UIR-002 | IR serialization | ✅ |
| UIR-003 | IR replay | ✅ |
| FRONTEND-001 | PHP echo | ✅ |
| FRONTEND-002 | C printf | ✅ |
| FRONTEND-003 | Python print | ✅ |
| BACKEND-001 | x64 instruction emission | ✅ |
| BACKEND-002 | PE32+ generation | ✅ |
| BACKEND-003 | Windows execution | ✅ |
| SOVEREIGN-001 | No CRT | ✅ |
| SOVEREIGN-002 | No LLVM | ✅ |
| SOVEREIGN-003 | No interpreter | ✅ |
| SOVEREIGN-004 | Native executable | ✅ |

## Bootstrap Chain

```
Stage 0: MASM → Sovereign Compiler Core
Stage 1: Sovereign Language → Sovereign Compiler Core
Stage 2: Sovereign Compiler builds itself
```

MASM is the seed compiler, not the final compiler.

## Dependencies

- **Allowed:** kernel32.dll (ExitProcess, VirtualAlloc, WriteFile)
- **Rejected:** MSVCRT, UCRT, LLVM, Python runtime, PHP runtime

## Roadmap

### v0.1 (Current)
- PHP echo, C printf, Python print
- UIR with 5 opcodes
- x64 emission
- PE32+ writer

### v0.2
- IR_ADD, IR_SUB, IR_COMPARE, IR_BRANCH, IR_STORE, IR_LOAD
- Variables: `$x = 1 + 2;`
- Conditionals: `if ($x > 2) echo "yes";`

### v0.3
- Self-hosting preparation
- Sovereign Language frontend
- Compiler rebuilds itself

## License

Sovereign RawrXD Infrastructure. All rights reserved.