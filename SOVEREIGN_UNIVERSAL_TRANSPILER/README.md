# Sovereign Universal Transpiler
## Language-Agnostic Native Compiler Kernel

### Architecture

```
ANY SOURCE LANGUAGE
       |
       v
+-------------+
|   Frontend  |  (Language-specific)
|   Adapter   |
+-------------+
       |
       v
+-------------+
|  Universal  |
|      IR     |
+-------------+
       |
       v
+-------------+
|   Native    |
|   Backend   |
+-------------+
       |
       v
   x64 PE
```

### Core Principle
Every language compiles to the same Universal Intermediate Representation (UIR), then to native x64 code. The backend is language-agnostic.

### Supported Languages (v0.1)
- PHP (`echo "text";`)
- C (`printf("text");`)
- Python (`print("text")`)

### Universal IR Opcodes
```
IR_NOP          = 0
IR_LOAD_CONST   = 1  ; Load string/number
IR_CALL         = 2  ; Call function
IR_RETURN       = 3  ; Return from function
IR_EXIT         = 4  ; Exit program
```

### Directory Structure
```
SOVEREIGN_UNIVERSAL_TRANSPILER/
├── kernel/
│   ├── lexer.asm          ; Shared tokenization
│   ├── uir.asm            ; Universal IR structures
│   ├── optimizer.asm      ; IR optimization
│   ├── emitter_x64.asm    ; x64 code generation
│   └── pe_writer.asm      ; PE32+ output
├── frontends/
│   ├── php_adapter.asm    ; PHP → UIR
│   ├── c_adapter.asm      ; C → UIR
│   └── python_adapter.asm ; Python → UIR
├── runtime/
│   ├── print.asm          ; Native print function
│   └── memory.asm         ; Heap allocator
└── build.bat              ; Bootstrap build
```

### Size Target
~4,000-5,000 lines of pure MASM x64

### Dependencies
- **Zero external dependencies**
- Only Windows API: `kernel32.dll`, `ntdll.dll`
- No MSVC CRT
- No LLVM
- No external assembler/linker at runtime

### Self-Hosting Path
```
Stage 0: MASM builds transpiler
Stage 1: Transpiler builds transpiler (self-host)
Stage 2: Transpiler builds RawrXD
```

### First Milestone
Input: `echo.php`
```php
<?php
echo "Hello from PHP";
```

Output: `echo.exe`
```
Hello from PHP
```

No PHP runtime. No interpreter. Native x64 executable.
