# RAWRXD_NATIVE_SELF_HOSTING_001 — Certification Gates

**Source tree:** F:\rawrxd  
**Compiler:** MSVC 2026 (MSVC++2026) via Visual Studio BuildTools 17.14.39  
**Constraint:** Zero new external dependencies. No Qt, no nlohmann/json, no vcpkg, no package downloads, no external runtime DLLs beyond Windows system components.  
**Objective:** Prove RawrXD can build itself — generation A builds generation B builds generation C from the same source revision.

---

## Certification Gates

| Gate | Requirement | Status | Evidence |
|------|-------------|--------|----------|
| SH-01 | IDE opens its own source project `F:\rawrxd` | PENDING | Launch RawrXD-Win32IDE-Native; verify project tree loads |
| SH-02 | Source discovery complete — all C/C++20/MASM sources enumerated | PENDING | File scan produces complete source inventory |
| SH-03 | Build dependency graph valid — CMake configures without errors | PASS | `cmake` configure succeeds; RawrXD-RE-Library + rawrxd-codex + RawrXD-Win32IDE-Native all build |
| SH-04 | Native C compilation passes | PASS | c_compiler_minimal.c compiles; cloud_api_client.cpp (C) compiles |
| SH-05 | Native C++20 compilation passes | PASS | RawrXD-RE-Library (C++20) compiled with /std:c++20; RawrXD_Disasm_Kernel.cpp compiles |
| SH-06 | Native MASM compilation passes | PARTIAL | ml64.exe available; disasm_smoke.cpp compiles as C++20 (MASM target not yet created for Disasm Kernel replacement) |
| SH-07 | Native PE/COFF linking passes | PASS | rawrxd-codex.exe linked successfully |
| SH-08 | RawrXD executable produced | PASS | F:\rawrxd\build\bin\Release\rawrxd-codex.exe exists and runs |
| SH-09 | New executable launches | VERIFIED | rawrxd-codex.exe list-arch and decode x64 produce correct output; RawrXD-Win32IDE-Native.exe --health-check returns ready=true |
| SH-10 | Native IDE initializes | VERIFIED | RawrXD-Win32IDE-Native.exe --health-check: "healthy (ready=true)" — production runtime, audit log, security runtime all initialized |
| SH-11 | New executable rebuilds itself | PENDING | RawrXD invokes its own compiler/linker on its source tree |
| SH-12 | Incremental rebuild verified | PENDING | Touch one source file; only affected objects recompile |
| SH-13 | Build failure rollback verified | PENDING | Introduce deliberate compile error; IDE preserves last known-good executable |
| SH-14 | No new external dependencies | VERIFIED | Only Win32 APIs, C++20 standard library, existing RawrXD-owned source (json_mini.h/cpp are RawrXD-owned) |
| SH-15 | Full self-hosting certification | BLOCKED | Requires SH-01, SH-02, SH-11, SH-12, SH-13 all PASS |

---

## Current Progress

**CODEX CLI (rawrxd-codex.exe):**
- Built: `F:\rawrxd\build\bin\Release\rawrxd-codex.exe`
- `list-arch`: outputs 10 architectures (arm64, arm32, thumb, thumb2, mips32, mips64, riscv32, riscv64, x86, x64)
- `decode x64 90`: NOP, 1 byte, SUCCESS
- `decode x64 CC`: INT3, 1 byte, SUCCESS
- `decode x64 C3`: RET, 1 byte, SUCCESS
- `decode x64 EB05`: JMP +5, 2 bytes, SUCCESS
- `decode x64 E801000000`: CALL +1, 5 bytes, SUCCESS
- `decode x64 4889C8`: MOV rax,rcx, 3 bytes, SUCCESS
- `decode x64 488B01`: MOV rax,[rcx], 3 bytes, SUCCESS
- `decode x64 488901`: MOV [rcx],rax, 3 bytes, SUCCESS
- `decode x64 48B80102030405060708`: MOV rax,imm64, 10 bytes, SUCCESS
- `decode x64 4883EC20`: SUB rsp,0x20 → SUCCESS (BLOCKER FIXED)
- `decode x86 90`: NOP → SUCCESS (BLOCKER FIXED — x86 architecture admitted)
- `decode arm64 90`: INVALID_ARCH (expected — ARM backend not yet implemented)
- `disasm`/`analyze` commands: "Unknown command" — not yet implemented in CLI

**x64 Disasm Kernel (replacement for missing RawrXD_Disasm_Kernel.asm):**
- `F:\rawrxd\src\asm\RawrXD_Disasm_Kernel.hpp/.cpp` — native C++20 x64 decoder
- `disasm_smoke.exe`: 25/25 tests PASS (including previously-failing 0x83 Group 1 and x86 admission)
- Implements `ReferenceDecoder_Decode` (previously undefined dllexport symbol)
- Linked into rawrxd-codex via RawrXD-RE-Library

**Build stabilization (all P0 fixes complete):**
- `IDETestAgent.h`: runTest() requires bool return; 20+ logging-only tests replaced with assertions
- `test_runner.cpp`: readiness polling (10s max, 100ms intervals) replaces Sleep(500); `--output` path configurable
- `Win32IDE_PowerShell.cpp`: -ExecutionPolicy Bypass removed; -EncodedCommand base64 transport; JSON parsed via RawrXD::Json (zero-dependency)
- `json_mini.h/cpp`: zero-dependency JSON parser/writer at F:\rawrxd\src/utils/

**RawrXD-Win32IDE-Native.exe:**
- Built: `F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe`
- `--health-check`: healthy (ready=true)
- Zero new external dependencies

---

## Remaining P1/P2 Work

| Item | Description | Priority |
|------|-------------|----------|
| Native LSP client | Replace Qt lsp_client.cpp with native JSON-RPC over Win32 pipes using json_mini | P1 |
| Settings persistence | Native JSON settings store with restart survival | P1 |
| Debugger variable inspection | Connect Win32IDE_Debugger.cpp to native panel | P1 |
| Terminal ConPTY | Verify Win32TerminalManager lifecycle, signals, exit codes | P1 |
| Extension activation | Remove false-success hosts, verify real extension load/execute | P1 |
| GPU backend selector | Verify device selection and runtime routing | P1 |
| Symbol index buildIndex | Fix empty SymbolIndex::buildIndex() | P0 |
| Extension hosts | Remove false-success ExecuteCommand/ExecuteScript | P0 |
| Model loader | Remove fake GGUF loader (if present locally) | P0 |

---

## Next Steps for Self-Hosting

1. **SH-11 (self-rebuild):** Wire RawrXD's own compiler (c_compiler_minimal.c or native_compiler) into the build pipeline so RawrXD can compile its own source
2. **SH-12 (incremental):** Verify CMake incremental rebuild works (touch one file, only affected object recompiles)
3. **SH-13 (rollback):** Implement last-known-good executable preservation and rollback on build failure
4. **SH-06 (MASM):** Create dedicated MASM target for the Disasm Kernel or verify ml64.exe integration
5. **SH-01/SH-02:** IDE project discovery and source inventory
