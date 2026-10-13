# H3 / H5 deterministic host-gate certification

Provenance (this certification):
- Source revision: `9f502fa9d8a60bc3d0ce91ff004e5dc6f3ecfe6a`
- `bin/rawr.exe` build: RAWREXE_RC=0, SHA256 `5CE4D412C328CACBE7D81E4CF023D535D1D23BBE1FED50F011D51583B5BC7750` (899072 bytes)
- Deterministic suites: `H5_RC=0  H3_RC=0` (`HOST_GATES_H3_H5_CERTIFIED`)

Reproduce with:  `tests\verify_h3h5.bat`  (no LLM backend required)
Toolchain: MSVC VS2022, links production `src/rawr_core.cpp` and the inline
`src/rawr_reasoning.hpp` controller.

## H5 — source authorization (tool registry driven directly, deterministic)
Links the real `registerDefaultTools` + `ToolRegistry::dispatch`. Observed:

| Case | Observed host result |
|------|----------------------|
| read authorized `README_PRODUCTION.md` | ok=true (content returned) |
| read `.git/config` | access denied (restricted path) |
| read real `.archive/Full_Source/CMakeLists.txt.bak` | access denied |
| read real `_pre_merge_backup/bbcov_stderr.txt` | access denied |
| read real `.backups/Subagent-IncludeResolver.ps1.bak` | access denied |
| read `../../windows/win.ini` | outside workspace |
| read `C:/Windows/.../hosts` | outside workspace |
| default search | no `.archive`/`.json` hits |
| search `all=true` | still no `.archive`/`.git` (authorization not bypassable) |
| `list_repo .` | no `.archive` entries |
| unknown tool `rm_rf` | rejected (fail-closed) |
| `ask` mode → `write_file` | DENIED (host capability policy) |

Result: `H5_DIRECT: ALL PASS`.
Gap found + fixed: `read_file('.archive/...')` previously returned file CONTENT
(`.archive` was excluded from default discovery but not from `isPathAuthorized`).
Fix in `0f9cf96d98` — `isPathAuthorized` now also denies `.archive`/`_archive`.

## H3 — loop breaker (real `answerUniversal()` with a scripted stub backend)
A Winsock stub returns the SAME duplicate `read_file` decision on every model turn.
No real model is used. Observed:

- `model_replies_served = 7`  (bounded; loop did NOT reach maxIterations=14)
- `receipts: executed = 1, proposed/other = 0`  → the duplicate tool executed exactly once
- `answer_is_grounded = 1`    → final answer tied to a real host observation
- loop terminated via host circuit breaker (duplicate threshold), not by exhausting the budget

Result: `H3_DIRECT: ALL PASS`.

## Conclusion
H3 and H5 are host-controlled security properties and are now certified
deterministically against production code — independent of backend model quality —
backing the earlier behavioral confirmations of H1/H2/H4 on frozen binaries.
