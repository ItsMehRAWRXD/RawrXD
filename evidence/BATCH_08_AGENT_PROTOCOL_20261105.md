# Batch 8 — Agent protocol / tool-result audit

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
CERTIFIED=0
PROMOTE=0
SOURCE_CHANGES_COMMITTED=4
NEW_RUNTIME_PASS_RECEIPTS=0

## Source repairs

- `74ccb0540ecb199b6fbf6791e62c080d90bed269`: reject signed, partial and out-of-range JSON uint32 tool arguments.
- `14adaf62148a138bbefca970ea0114bd05380942`: remove only enclosing Markdown fences; preserve embedded backticks.
- `8c3470c71f1c8ac3a7320e74af85053999414606`: include actual tool exit code and success/failure state in model-visible tool result.
- `03c7968f23831b28c51cc3d2089ae8d0d3945f2d`: explicit `<cstdint>` dependency.

## Fifteen distinct validation cases (NOT EXECUTED)

| ID | Case | State |
|---|---|---|
| B8-01 | uint32 normal decimal | PENDING |
| B8-02 | uint32 negative value | PENDING |
| B8-03 | uint32 leading plus sign | PENDING |
| B8-04 | uint32 value > UINT32_MAX | PENDING |
| B8-05 | uint32 trailing garbage | PENDING |
| B8-06 | uint32 empty value fallback | PENDING |
| B8-07 | tool JSON argument containing literal backticks | PENDING |
| B8-08 | fully fenced tool call | PENDING |
| B8-09 | unfenced tool call | PENDING |
| B8-10 | partial/malformed fence handling | PENDING |
| B8-11 | successful tool result includes exit=0 | PENDING |
| B8-12 | failing tool result includes nonzero exit | PENDING |
| B8-13 | empty successful result explicitly represented | PENDING |
| B8-14 | reinjection into next generation rather than same step | PENDING |
| B8-15 | maxSteps exhausted before reinjection must not claim model saw result | PENDING |

These are 15 **audit checks**, not 15 completed functional blockers. No build, unit-test, or runtime evidence was generated in this batch.

## Remaining priority blockers

Production parser isolated test target; actual model-originated `editFiles` tool invocation; explicit mutation approval; exact disk persistence/readback; Deep2 numerical correctness; GPU correctness; native IDE GUI recovery; soak/stress; reproducible packaging; T25 independent certification.

The audited `~dev/src/rawr_agent_dispatch.cpp` is documented as a read-only audit tool provider, so do not introduce unrestricted file mutation into it. Locate the existing authorized CLI edit path and connect it to the intended agent surface with a clear approval gate.
