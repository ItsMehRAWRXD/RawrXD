# Batch 21 — Dispatcher scan integrity and live GitHub static audit

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
CERTIFIED=0
PROMOTE=0

## Source defects addressed

1. `audit.scan` previously ignored `runSourceScan()` return value and could emit PASS on incomplete/failed scans. Now fail-closed on failure or mismatched counters. Commit `fcfd2608f40ae2f6fe6087a4a210257e6667740c`.
2. `audit.files_reviewed` ignored ledger rejection and always returned success. Now propagates failure. Commit `688db0dea2cdf6e923b7f6778c0c130bba6db2ab`.
3. `audit.candidate.read` did not check source freshness or scan epoch before presenting evidence. Now rejects stale/missing/epoch-mismatched candidates. Commit `a2efc04b763c133e8bbf979776b7a6ffcf8c67e3`.
4. `workspace.list` allowed oversized model-supplied limit and allocated proportional to all enumerated files. Now caps limit at 2000 and allocation accordingly. Commit `89b5b45e2056acdce04fec111edc8d5cd258bf66`.
5. The real dispatcher translation unit was absent from the portable compile checks. Added C++20 syntax-only compile to Linux workflow. Commit `46f38100ab2b65c0ad6c0f3380fc821c4b0cfd00`.

## Fifteen static source assertions executed against GitHub-fetched branch

01 PASS scan bool enforced
02 PASS scan counters enforced
03 PASS file review failure handled
04 PASS candidate freshness checked
05 PASS candidate epoch checked
06 PASS candidate read containment
07 PASS search path containment
08 PASS full-line code search
09 PASS full-line symbol search
10 PASS symbol identifier guard
11 PASS workspace listing bounded
12 PASS candidate offset bounded
13 PASS both tool output streams
14 PASS receipt digest verification
15 PASS real dispatcher CI syntax check present

TOTAL=15/15 static assertions PASS. These are text-level checks, NOT C++ compilation, linked runtime tests, 15 closed functional blockers, or native Windows certification.

## Execution limits

Attempt to access the GitHub repository from the local container via `git ls-remote` failed DNS resolution. GitHub connector allowed inspecting and committing source, but the full native Windows IDE and local model/GPU are not accessible from this environment. GitHub Actions workflow success has not been established. No 100% completion claim.

## Outstanding certification

Windows build, CTest, actual model tool invocation, mutation authorization, editFiles exact disk readback, ToolResult reinjection, T05 strict cancellation, crash recovery, Deep2 CPU/GPU numerical correctness, soak, packaging and independent certification remain to be verified.
