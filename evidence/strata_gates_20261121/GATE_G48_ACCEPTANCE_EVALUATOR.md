# Gate G48 — Native acceptance evaluator => PASS

The agent loop's completion gate (`runAgentLoop` in `src/rawr_cli.cpp`) is a
deterministic acceptance evaluator, independent of model quality. It gates
`completed=true`/`EXIT_OK` on real tool receipts and real build/test success.

## Evaluator logic (source)
- `ungrounded` (success/facts claimed with no successful tool receipt) -> rejected;
  after grounding strikes -> **fail closed, completed=false** (lines ~1016-1022).
- `negated` (final reports an incomplete/failed run) -> **completed=false, EXIT_FAIL**
  (lines ~1025-1033).
- `completed=true` only on a genuine final answer backed by real receipts (line ~1041).

## Deterministic acceptance cases (runtime)
| Scenario | Expected | Observed |
| --- | --- | --- |
| Model claims success with no receipts | Reject | `final answer rejected (execution_without_build_receipt) strike 1` -> exit 1 |
| Source edited but build failed | Reject | `run_build exit=1`, `run_tests` fail -> `exit=1`, completed=false |
| Fresh build + all tests passed | Accept | G47: `run_build ok`, `run_tests ok`, `exit=0`, `100% tests passed` |

Timeout/cancellation and "required tests skipped" are covered by the same
`c.completed && c.exitCode==0` gating in the `run_build`/`run_tests` tools and
the `ro.canceled` checkpoint path (lines ~1083-1086): a timeout yields
`completed=false`, and a skipped test makes ctest exit non-zero -> rejected.

## Conclusion
G48 acceptance evaluator behaves deterministically and does not fabricate
success: it rejects ungrounded claims, failed builds, and failed tests, and
accepts only a fresh build with all tests passing.

## Ledger
```
G48=PASS
REMAINING=71
```