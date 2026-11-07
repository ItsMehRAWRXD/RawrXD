# Batch 7 — End-to-end agent blockers (source-grounded)

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
CERTIFIED=0
PROMOTE=0

## Verified source findings and repairs

1. **Tool-result reinjection accounting**: `run_agent_session` set `sawToolResult=true` immediately after pushing tool output into history, even if `maxSteps` ended before the next generation. Repaired in commit `4cc0ba24ba8e0068bdc60c684b949fb2741b5d0d`. The flag now sets when a later generation is about to consume the history.
2. **Protocol malformed tags**: `parseReply` rejected some but not all misplaced or duplicate closing tags. Strengthened in commit `de6ff6e1c12c71ffa80586bd5d8564a1846e0286`.

## Fifteen remaining high-priority blockers

| ID | Area | Disposition |
|---|---|---|
| E01 | Production parser isolated deterministic test target | OPEN |
| E02 | Parser invalid JSON payload rejection | OPEN |
| E03 | Model-originated tool-call output verified | OPEN |
| E04 | Registered mutating `editFiles` agent tool availability | OPEN — current read-only audit registry does not register this tool |
| E05 | Mutation authorization boundary | OPEN |
| E06 | Exact `editFiles` disk persistence | OPEN |
| E07 | Disk readback and SHA receipt | OPEN |
| E08 | ToolResult reinjection runtime proof | OPEN — accounting source repaired, no runtime receipt |
| E09 | Multi-step tool-call recovery | OPEN |
| E10 | Cancellation and timeout end-to-end | OPEN |
| E11 | Deep2 numerical correctness | OPEN |
| E12 | GPU inference correctness | OPEN |
| E13 | Native IDE GUI and crash recovery | OPEN |
| E14 | Soak/stress and reproducible packaging | OPEN |
| E15 | Independent T25 certification and promotion | OPEN |

These are distinct *open blockers*, not fifteen claimed fixes. Evidence for E04 is scoped to the audited `~dev/src/rawr_agent_dispatch.cpp` registration surface; other agent implementations may register mutating tools.

## Next required work

- Build and execute a production-parser unit test with valid, malformed, reordered, multi-call and bare-tool inputs.
- Inspect the actual `editFiles` CLI path and ensure the model can reach it only with explicit mutation approval.
- Require a real edit fixture, exact disk readback, and a second generation that consumes the tool result.
- Preserve `CERTIFIED=0` until runtime receipts cover all gates.
