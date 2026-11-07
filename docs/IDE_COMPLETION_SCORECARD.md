# RawrXD IDE completion and certification scorecard

Updated: 2026-11-05. Branch: fix/deep2-multimodel-safety-20261025.

## Definitions

- **Implementation estimate**: provisional 68% historical estimate; not a measured
  current-source feature inventory. Do not increment from individual commits.
- **Production certification**: 0% (not certified; PROMOTE=0).
- **Headless suite coverage**: 3/5 *current-revision* suites independently verified
  after latest changes (CLI numeric 25/25, extension bridge 37/37, JS compatibility bridge 15/15; all tested files matched Git blob SHAs).
- **Full IDE end-to-end**: NOT VERIFIED. No native Windows build, physical GUI,
  extension activation, package install, or soak receipt on this revision.

## Fifteen priority gates (none may close on source changes alone)

| Gate | Scope | Evidence required | Status |
|---|---|---|---|
| G01 | Command registry | Current-SHA 69-case headless PASS | OPEN |
| G02 | Extension bridge | Current-SHA 37-case headless PASS | PASS (2026-11-05; GCC/UBSan, Git blob SHA matched) |
| G03 | JS fail-closed bridge | Current-SHA 15-case headless PASS | PASS (2026-11-05; GCC/UBSan, Git blob SHA matched; **not** real QuickJS activation) |
| G04 | Bridge-to-registry | Current-SHA 15-case headless PASS | OPEN |
| G05 | CLI numeric policy | Current-SHA 25-case headless PASS | PASS (2026-11-05; GCC/UBSan, Git blob SHA matched) |
| G06 | Real QuickJS extension activation | Load, command, deactivate, unload | OPEN |
| G07 | VSIX lifecycle | Safe install, reject, rollback, uninstall | OPEN |
| G08 | CLI read/edit/write | Real executable, disposable disk fixture and hashes | OPEN; separate inference CLI canned generate/chat/benchmark now fail closed, not a tool-edit PASS |
| G09 | CLI authorization | Deny/approve matrix, exact disk effects | OPEN |
| G10 | CLI cancellation | Timeout, process exit, no stale writes | OPEN |
| G11 | Native file workflows | Save, Save As, reopen, Unicode, external edits | OPEN |
| G12 | Native UI workflows | Tabs, palette, keyboard, terminal, crash recovery | OPEN |
| G13 | Clean Windows build | MSVC build + executable launch receipt | OPEN |
| G14 | Package integrity | Clean install, SHA, dependency audit, uninstall | OPEN |
| G15 | Daily-use soak | Integrated repeated workflow and crash-free receipts | OPEN |

## Run without inference

From the repository root with Python 3 and GCC/Clang available:

```sh
python3 tools/run_headless_acceptance.py --output headless-acceptance-receipt.json
```

The runner fails nonzero on any compile/test failure, includes source SHA-256
hashes and raw command outputs, and never claims GUI or model acceptance.
The complete five-suite runner has not been independently executed on the current GitHub SHA. The CLI numeric test was independently compiled and executed on exact Git blob-matched source.

Do not equate a percentage of test cases with percentage of IDE completion.

## November 5 additional source audit findings

- `~dev/rawrxd/src/core/rawrxd_cli_main.c` was returning success for canned
  generation, rotating scripted chat and sleep-derived synthetic inference TPS.
  Those three modes now fail closed with exit code 3 until wired to a real backend.
  This is a **source remediation**, not an executed end-to-end CLI PASS.
- The 69-case central registry test and 15-case bridge integration test remain
  unexecuted on the current revision. Do not mark either PASS from source alone.
- `main` is an older tree than the working development branch. The controlling
  audit revision is `fix/deep2-multimodel-safety-20261025` unless superseded.
