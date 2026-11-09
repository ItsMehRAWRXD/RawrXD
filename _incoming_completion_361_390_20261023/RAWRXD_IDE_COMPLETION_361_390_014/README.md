# RAWRXD IDE COMPLETION 361–390 — SOURCE DROP 014

## Delivered (actual code)
- `src/main.cpp`: `rawr-runtime-gates`, a portable dependency-free C++20 runtime acceptance checker.
- `tests/`: negative (unmeasured), positive (**SYNTHETIC ONLY**), malformed duplicate-key regression fixtures.
- `docs/ROADMAP_361_390.md`: 30 explicitly unverified engineering moves with acceptance conditions.
- `CMakeLists.txt`: standalone C++20 build; does not alter repository CMake.

## Contract
`rawr-runtime-gates evaluate <measurements.txt> <new_receipt.json>`; measurements and logs must live in same evidence directory. Evidence is simple bounded `key=value` text. `*_log=relative/path.txt` files must exist, must be nonempty and <=64 MiB. Absolute, parent-traversal and `\` paths rejected. Tool never executes claimed tests; it checks values supplied by a producer. Evidence provenance is **not cryptographically authenticated**. Positive synthetic fixtures must never be used as production certification. For real field certification, independent observer review, actual binary/model/source hashes, and execution harness integration are required.

Exit status 0 = all 20 evaluated gates passed; 1 = incomplete/not-certified; 2 = malformed input or write failure. Existing output receipts are never overwritten; use unique names. Existing staged files block publication.

## Build
```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```
Linux portability verification: GCC + CMake build and 3/3 CTests PASS. Windows MSVC compilation and actual RawrXD integration **NOT RUN**.

## Standalone demonstration
`rawr-runtime-gates evaluate tests/partial/evidence.txt my-first-receipt.json` returns exit 1 and outputs a NOT_CERTIFIED receipt. Positive synthetic fixture exists solely to test the evaluator's logic.

## Source preservation and integration
Do not copy over `F:\rawrxd` or `G:\~dev\rawrxd` without a reviewed integration. Add this as a new CMake subdirectory, or compile it separately and feed real traces from the Deep2/Win32/agent harness. Keep branch `cert/gpu-forward-child-ladder-20260909` and existing recovery snapshots intact. No Qt/Electron/OpenSSL/nlohmann/json dependencies added. CMake/build toolchain still required.

## Outstanding security limits
Evidence files can be forged or edited; no signature checking. File symlink check is not race-proof. Atomic no-overwrite publication uses filesystem rename and may differ on platforms. The evaluator is a QA tool, not a runtime monitor or substitute for model correctness tests.
