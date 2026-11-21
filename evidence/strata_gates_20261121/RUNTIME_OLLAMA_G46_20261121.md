# Runtime evidence — Ollama inference + agentic policy (2026-11-21)

Deep2-independent runtime checks (no edits to the concurrent worker's deep2
files).

## Ollama chat inference => PASS
`rawr ask "What is 2+2? Reply in one short sentence." --backend ollama`
- exit 0
- answer: `2+2 is 4.`
- `context: 1 relevant fact(s) recovered from memory`
This exercises the real Ollama HTTP path (model from the live registry,
`llama3.2:3b` family) and produces a correct decoded answer.

## Agentic tool loop policy (G46/G47) => finding
The same run logged:
`[..] answer: tool loop disabled by host policy for this question`
`(no tools were executed; this answer is not evidence-backed)`
- The agentic tool-execution loop is **present but gated OFF by host policy**
  for ordinary `ask` prompts. G46 (native agentic tool execution) therefore
  requires (a) enabling the agentic tool policy and (b) a runtime test that
  shows a tool actually executing and its output verified.

## Performance (G68/G71) => partial
- Ollama chat latency measured only as total wall time; rigorous
  first-token-latency and prefill/decode TPS require instrumented streaming
  timing (RAWRXD_ASK_TRACE / per-token timestamps). Not yet certified.

## Ledger delta
```
G56=PASS (live Ollama health)
OLLAMA_CHAT_INFERENCE=PASS
G46_TOOL_LOOP=POLICY_DISABLED (needs enablement + runtime test)
G47_AUTONOMOUS_LOOP=POLICY_GATED
REMAINING=81
```