# Batch 17 — Agent feedback and Windows CI

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
PROMOTE=0
CERTIFIED=0

## Audited product defects

1. The agent chose only stdout on success or only stderr on failure, discarding useful information from the other stream. This could hide tool diagnostics from the model.
2. The `sawToolResult` flag was set as soon as a prompt with history was assembled, even if the subsequent model generation returned no text. This could overstate successful reinjection.

## Commits

- `a3963a5064246a14d9802d568df78f9ba7ed7d0f`: preserve and label both stdout and stderr for model reinjection.
- `48122f0eb9e5630088c19b42f400834dde982179`: only mark ToolResult seen after nonempty subsequent generation.
- `607f8886f4c792188714fb02ccdedd4627bd229f`: add Windows MSVC parser and receipt-verifier CI job.

## 15 remaining end-to-end acceptance gates

1. Source build on Windows.
2. Native CTest suite.
3. Parser protocol regression suite.
4. Registered tool catalog routing.
5. Actual model-originated tool call.
6. Mutation authorization and denial.
7. Authorized editFiles disk write.
8. Exact byte-level editFiles disk readback.
9. ToolResult reinjection to subsequent model generation.
10. Strict A→Stop→B cancellation.
11. Crash recovery after forced termination.
12. Deep2 CPU numerical correctness.
13. GPU numerical correctness.
14. GUI soak and package verification.
15. Independent final certification.

## Verification and limits

GitHub source commits confirmed; CI job execution and results not yet confirmed. The Windows workflow tests only portable parser and Python verifier, not the full Win32IDE binary. The two agent loop repairs have not been exercised against an actual local model in this session. These 15 gates are the outstanding acceptance obligations, not 15 claims of repaired product defects. No promotion or certification is authorized.
