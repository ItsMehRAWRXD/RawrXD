# RawrXD IDE Completion 013 — moves 331–360

Portable C++20 standalone runtime-evidence gate analyzer. No Qt, no third-party libraries.

Build: `cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure`

Run: `rawr-evidence evaluate tests/partial.txt receipt.json`

The partial fixture models the *reported* Win32 build/launch and Q2_K finite activation status; it deliberately returns `NOT_CERTIFIED` (exit 1) for missing runtime data. `tests/full.txt` is **synthetic test data**, NOT a claim of real system certification.

Do not treat `PASS` strings in a manually prepared input file as independently attested evidence. Production integration must emit inputs from command output, hashes, device logs and actual GUI instrumentation, and bind each receipt to its source commit and artifact SHA256. Missing keys never pass. The receipt is a gate-calculation result, not proof of underlying measurements.

Run against Windows MSVC and integrate into `F:\rawrxd` / `G:\~dev\rawrxd` only after reviewing source provenance, preserving original files and an existing snapshot. Nothing in this ZIP modifies your repository or local models.

See docs/ROADMAP_331_360.md.
