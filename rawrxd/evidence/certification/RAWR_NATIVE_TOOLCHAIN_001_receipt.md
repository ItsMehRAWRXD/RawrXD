# RAWR_NATIVE_TOOLCHAIN_001 Certification Receipt

**Date:** 2026-09-22
**Certification ID:** RAWR_NATIVE_TOOLCHAIN_001
**Status:** PASS

## Authority Checks

| Gate | Result |
|---|---|
| `RETURN_CONSTANT` | PASS |
| `INTEGER_ADD` | PASS |
| `CONDITIONAL_BRANCH` | PASS |
| `LOOP` | PASS |
| `COFF_WRITER` | PASS |
| `PE64_LINKER` | PASS |
| `HELLO_EXE_CREATED` | PASS |
| `HELLO_EXE_RUN` | PASS |
| `HELLO_EXE_EXIT` | 0 |
| `EXTERNAL_COMPILER_USED` | 0 |
| `EXTERNAL_ASSEMBLER_USED` | 0 |
| `EXTERNAL_LINKER_USED` | 0 |
| `EXIT_CODE` | 0 |

## Fixes Applied

1. **InstructionEncoderX64.cpp** — `encodeALU` register-to-register path corrected the ModR/M `reg`/`rm` field direction. Previously `ADD EAX, ECX` was encoded as `ADD ECX, EAX` due to swapped `encodeModRMSIB` arguments.
2. **RawrPE64Linker.cpp** — Multiple PE header bugs fixed:
   - `e_lfanew` field in DOS header was being corrupted by a `writeU32` call; replaced with direct byte writes at offset 0x3C.
   - `SizeOfInitializedData` was always 0; now computed from import table size.
   - Linker version fields were U16 instead of U8, corrupting optional header structure.
   - Subsystem version fields were zero; set to 5.0 (Windows XP+) to satisfy loader.
   - `buildIdat` computed `Name` RVA before writing DLL names, pointing to empty hint entries. Reordered so Name RVA is patched after the DLL name is written.
3. **JITAssembler.hpp** — Added move constructor and move assignment operator to `JITFunction` to prevent double-free heap corruption when returned by value from `finalize()`.

## Source Changes

- `rawrxd/src/compiler_backend/InstructionEncoderX64.cpp`
- `rawrxd/src/compiler_backend/RawrPE64Linker.cpp`
- `rawrxd/src/sovereign/puppeteer/JITAssembler.hpp`
- `rawrxd/certification/native_toolchain_cert.cpp`
- `rawrxd/build/compile_cert.bat`

## Environment

- **Compiler:** VS2022 BuildTools v17.14.39, MSVC 14.44.35207
- **Target:** x64
- **Flags:** `/nologo /EHsc /std:c++17`
- **Build Script:** `rawrxd/build/compile_cert.bat`

## Next Milestone

`SUNSHINE_CORE_001` — Minimum native runtime for playable benchmark.
