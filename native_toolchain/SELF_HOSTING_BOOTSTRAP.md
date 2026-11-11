# Self-Hosting Bootstrap Plan

**Date**: 2026-07-08  
**Status**: Ready for Execution  
**Goal**: Compile `c_compiler_minimal.c` with itself

---

## 🎯 The Bootstrap Challenge

The ultimate test of a self-hosting toolchain: **Can the compiler compile itself?**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BOOTSTRAP PHASES                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Phase 0: Cross-Compile (DONE)                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                   │
│  │   MSVC    │───▶│  c_compiler │───▶│  Stage0     │                   │
│  │  (Host)   │    │  _minimal.c │    │  c_compiler.exe│                   │
│  └─────────────┘    └─────────────┘    └─────────────┘                   │
│                                                                             │
│  Phase 1: Self-Compile (NEXT)                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                   │
│  │   Stage0  │───▶│  c_compiler │───▶│  Stage1     │                   │
│  │  (Host)   │    │  _minimal.c │    │  c_compiler.exe│                   │
│  └─────────────┘    └─────────────┘    └─────────────┘                   │
│                                                                             │
│  Phase 2: Verification (CRITICAL)                                          │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                   │
│  │   Stage0  │───▶│  Compare    │◄───│   Stage1    │                   │
│  │  (Host)   │    │  Binaries   │    │  (Self)     │                   │
│  └─────────────┘    └─────────────┘    └─────────────┘                   │
│                                                                             │
│  Phase 3: Convergence (OPTIONAL)                                           │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                   │
│  │   Stage1  │───▶│  c_compiler │───▶│  Stage2     │                   │
│  │  (Self)   │    │  _minimal.c │    │  c_compiler.exe│                   │
│  └─────────────┘    └─────────────┘    └─────────────┘                   │
│                                                                             │
│  Stage2 should be bit-identical to Stage1 (convergence achieved)         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📋 Prerequisites Checklist

Before attempting bootstrap:

- [x] `c_compiler_minimal.c` compiles with MSVC
- [x] `c_compiler_minimal.exe` produces working assembly
- [x] `minimal_assembler.exe` assembles to object files
- [x] `linker_with_imports.exe` links to executables
- [x] Full pipeline tested end-to-end

---

## 🔧 Bootstrap Procedure

### Step 1: Prepare Environment

```batch
:: Create bootstrap directory
mkdir d:\rawrxd\native_toolchain\bootstrap
cd d:\rawrxd\native_toolchain\bootstrap

:: Copy source and tools
copy ..\c_compiler_minimal.c .
copy ..\c_compiler_minimal.exe .\stage0_c_compiler.exe
copy ..\minimal_assembler.exe .
copy ..\linker_with_imports.exe .
```

### Step 2: Self-Compile

```batch
:: Use Stage0 to compile the source
stage0_c_compiler.exe c_compiler_minimal.c stage1_output.asm

:: Assemble the output
minimal_assembler.exe stage1_output.asm stage1_c_compiler.obj

:: Link to executable
linker_with_imports.exe stage1_c_compiler.obj stage1_c_compiler.exe
```

### Step 3: Verify Functionality

```batch
:: Test Stage1 compiler
stage1_c_compiler.exe test_input.c test_output.asm

:: Compare outputs
fc /b stage1_output.asm test_output.asm
```

### Step 4: Binary Comparison

```batch
:: Compare Stage0 and Stage1 binaries
fc /b stage0_c_compiler.exe stage1_c_compiler.exe

:: If not identical, analyze differences:
:: - Timestamps in PE header
:: - Section alignment
:: - Symbol table ordering
:: - Padding differences
```

---

## 🧪 Expected Results

### Success Criteria

| Metric | Expected | Acceptable |
|--------|----------|------------|
| Compilation | Stage1 produced | No crash |
| Output ASM | Valid assembly | Syntactically correct |
| Functionality | Identical to Stage0 | Within tolerance |
| Binary diff | Near-zero | Structural only |

### Known Differences (Non-Critical)

1. **PE Timestamps** - Different compilation times
2. **File Alignment** - Padding may differ
3. **Symbol Ordering** - Hash table ordering
4. **Debug Info** - Path strings differ

### Critical Differences (Must Fix)

1. **Code generation** - Different instructions
2. **Memory layout** - Different section sizes
3. **Calling conventions** - ABI mismatch
4. **Optimization** - Different optimization levels

---

## 🚨 Troubleshooting

### If Stage1 crashes:

```
1. Check if Stage0 output ASM is valid
2. Verify assembler produces correct object
3. Check linker imports are correct
4. Compare memory maps between Stage0 and Stage1
```

### If outputs differ:

```
1. Run both compilers with same input
2. Diff the ASM outputs
3. Identify first differing instruction
4. Trace back to source code cause
```

### If binaries differ significantly:

```
1. Use dumpbin /headers on both
2. Compare section sizes
3. Check entry points
4. Verify imports match
```

---

## 📊 Success Metrics

```
Bootstrap Complete When:
✅ Stage1 compiles without errors
✅ Stage1 output is valid assembly
✅ Stage1 produces working executables
✅ Stage1 can compile c_compiler_minimal.c
✅ Stage2 (if built) matches Stage1 functionality

Bonus Points:
⭐ Stage1 binary is smaller than Stage0
⭐ Stage1 compiles faster than Stage0
⭐ Stage2 is bit-identical to Stage1
```

---

## 🚀 Post-Bootstrap

Once bootstrap succeeds:

1. **Document the achievement** - This is rare
2. **Freeze the compiler** - Lock working version
3. **Performance benchmark** - Compare Stage0 vs Stage1
4. **Package for distribution** - Others can bootstrap
5. **Plan next features** - Extend the language

---

## 📝 Bootstrap Script

```batch
@echo off
:: bootstrap.bat - Automated Self-Hosting Bootstrap

echo ============================================
echo   RawrXD Compiler Self-Hosting Bootstrap
echo ============================================

set STAGE0=stage0_c_compiler.exe
set STAGE1=stage1_c_compiler.exe
set SOURCE=c_compiler_minimal.c

:: Phase 1: Self-compile
echo [Phase 1] Self-compiling...
%STAGE0% %SOURCE% stage1.asm
if errorlevel 1 goto :fail

:: Phase 2: Assemble
echo [Phase 2] Assembling...
minimal_assembler.exe stage1.asm stage1.obj
if errorlevel 1 goto :fail

:: Phase 3: Link
echo [Phase 3] Linking...
linker_with_imports.exe stage1.obj %STAGE1%
if errorlevel 1 goto :fail

:: Phase 4: Verify
echo [Phase 4] Verifying...
%STAGE1% %SOURCE% stage2.asm
if errorlevel 1 goto :fail

:: Phase 5: Compare
echo [Phase 5] Comparing outputs...
fc /b stage1.asm stage2.asm > nul
if errorlevel 1 (
    echo [WARNING] Outputs differ
) else (
    echo [SUCCESS] Outputs match!
)

echo ============================================
echo   Bootstrap Complete!
echo   Stage1: %STAGE1%
echo ============================================
goto :end

:fail
echo [FAILED] Bootstrap failed at Phase %ERRORLEVEL%
exit /b 1

:end
```

---

**Ready to execute bootstrap?** The toolchain is ready! 🔥
