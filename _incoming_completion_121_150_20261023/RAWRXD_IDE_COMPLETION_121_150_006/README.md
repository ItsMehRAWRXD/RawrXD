# RAWRXD IDE COMPLETION — SOURCE DROP 006 (Moves 121–150)

**Purpose:** Make the completion roadmap measurable in the **actual RawrXD IDE**, not just generate planning text.

## Implemented
- Pure C++20 independent certification-gate library, no external code libraries.
- 30 named gates (121–150), defaulting to NOT_RUN.
- Atomic JSON receipt writing (same-filesystem rename; destination overwrite may require removal on Windows).
- Strict results-file parser: invalid IDs/statuses/duplicates rejected, PASS requires evidence string.
- CTest checks for parser, gate coverage, defaults, output, and basic relative-path validation.

**Not implemented:** Windows HWND tests, full extension host, model execution, Mach-O/iOS signing, or actual IDE integration. These require adapters into your repository; roadmap entries are not certified.

## Build
```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Usage
```powershell
.\build\Release\rawr-ide-gates.exe init F:\rawrxd\evidence\IDE_121_150\receipt.json
.\build\Release\rawr-ide-gates.exe apply results.txt F:\rawrxd\evidence\IDE_121_150\receipt.json
```
Results file format:
```
121|PASS|evidence/real_hwnd_dump.json
136|FAIL|evidence/q2k_gpu_mismatch.log
137|BLOCKED|evidence/phi3_av.log
```
Status is recorded as supplied by an operator; this tool does not execute or independently authenticate referenced tests. Do not use it to claim certification without checking evidence.

## Safety notes
- No Qt/OpenSSL/other bundled dependency. Uses standard C++20 and standard file I/O.
- Does not modify model files or existing RawrXD repository sources.
- Do not put keys, passwords, or auth tokens into result strings.
- Use a controlled evidence directory; ensure file permissions and review receipts before publication.
- No active Apple signing is included. Authorized Apple signing and real-device deployment remain required.

See `docs/ROADMAP_121_150.md` for all 30 work items, failure boundaries, and priority order.
