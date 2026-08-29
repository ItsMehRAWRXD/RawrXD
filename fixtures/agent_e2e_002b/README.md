# AGENT-E2E-002b — GGUF-directed autonomous repair

## Invariant

GGUF prompt → model TOOL_CALL → actual source mutation → build 0 → run 0 → expected stdout → final answer.

Forbidden: demo-break prepass, canned TOOL_CALL, repair injected outside the model, SUCCESS string as proof.

## Headline

`04_logic_bug` — runtime logic with no compiler diagnostic (evolved from AGENT-E2E-002/09).
