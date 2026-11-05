# RawrXD IDE completion and certification scorecard

Updated: 2026-11-05. Branch: fix/deep2-multimodel-safety-20261025.

## Definitions

- **Implementation estimate**: provisional 68% historical estimate; not a measured
  current-source feature inventory. Do not increment from individual commits.
- **Production certification**: 0% (not certified; PROMOTE=0).
- **Headless suite coverage**: 0/5 *current-revision* suites independently verified
  after latest changes. Earlier 25/25 extension-bridge production-source PASS
  applied to an older SHA and does not certify the updated ownership API.
- **Full IDE end-to-end**: NOT VERIFIED. No native Windows build, physical GUI,
  extension activation, package install, or soak receipt on this revision.

## Fifteen priority gates (none may close on source changes alone)

| Gate | Scope | Evidence required | Status |
|---|---|---|---|
| G01 | Command registry | Current-SHA 69-case headless PASS | OPEN |
| G02 | Extension bridge | Current-SHA 37-case headless PASS | OPEN |
| G03 | JS fail-closed bridge | Current-SHA 15-case headless PASS | OPEN |
| G04 | Bridge-to-registry | Current-SHA 15-case headless PASS | OPEN |
| G05 | CLI numeric policy | Current-SHA 25-case headless PASS | OPEN |
| G06 | Real QuickJS extension activation | Load, command, deactivate, unload | OPEN |
| G07 | VSIX lifecycle | Safe install, reject, rollback, uninstall | OPEN |
| G08 | CLI read/edit/write | Real executable, disposable disk fixture and hashes | OPEN |
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
The runner has not been independently executed on the current GitHub SHA.

Do not equate a percentage of test cases with percentage of IDE completion.
