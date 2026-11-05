# Batch 9 — Agent parser parity and 15-case protocol matrix

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
PROMOTE=0
CERTIFIED=0

## Concrete findings

1. The headless agent's production parser in `~dev/src/rawr_agent.cpp` and the portable selftest parser in `~dev/src/rawr_agent_parse_only.cpp` had diverged. The selftest implementation still stripped every backtick and accepted incomplete/multiple tagged tool calls.
2. The production parser accepted arbitrary non-object text inside tagged `<args>` blocks.
3. The existing portable CI job only executed registry tests; it did not run the available protocol selftest.

## Changes committed

- `b97e6b082afa456f685992a29d972c4bb9a0f8a7`: reject tagged non-object argument framing.
- `aae8a7227aa5ff4b7bbb705eaa36c0821ee863d2`: synchronize portable parser behavior to production.
- `61e63cb35c3277944505cf7c03f3c4f6c7d05c5b`: add 15 adversarial protocol cases, and adjust the existing fenced-call case to a multiline Markdown fence.
- `59c65adc0961a683548c209298e995e6bfca3a96`: compile and run portable protocol selftest in the agent CI workflow.

## Fifteen new protocol cases

01 Tagged file.read with object arguments.
02 Tagged audit.coverage with empty object.
03 Bare file.read invocation.
04 Bare code.search invocation.
05 Empty tagged args default to empty object.
06 Missing closing tool tag rejected.
07 Multiple tagged tool calls rejected.
08 Duplicate args block rejected.
09 Stray closing args tag rejected.
10 Args without tool rejected.
11 Non-object tagged args rejected.
12 Args before tool rejected.
13 Stray closing tool tag rejected.
14 Plain final answer accepted.
15 Plain final answer with backticks preserved.

## Important limitation

This change synchronizes the two parser copies but does not yet remove duplication. A future refactor should extract the parser into one shared translation unit/header used by both the production agent and the selftest. Until then, drift can recur.

No actual CI result, Windows build receipt, native GUI test, or model-originated editFiles persistence receipt was available in this batch. GitHub's commit-status endpoint returned no statuses, and its commit workflow-run lookup returned no runs. These are NOT_VERIFIED, not PASS.

## Remaining highest-priority gates

Model-originated tool-call execution; explicit mutation authorization; exact editFiles disk readback; tool-result consumption; Deep2 numeric correctness; GPU execution; T05/T10/T18/T19 Windows integration; T24 package verification; T25 independent certification.
