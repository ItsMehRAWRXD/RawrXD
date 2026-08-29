# AGENT-E2E-002b interim status (2026-08-29)

## Unblocks landed on F authority
1. loadModel now initializes QuantKernelRegistry + ThreadPool + KV (Agentic loadModel-only path)
2. LinearW_Range auto-inits empty registry
3. RAWRXD_GREEDY honored by generateText
4. Zero-embed holes (token 35 / `<0x20>`) tolerated (WARN_EMBED)
5. Diagnostic spam gated: KERNEL / B3_STATE / EMBED_RAW / B3_LOGITS / GREEDY top10

## BOS still green
test_generate_one_token EXPECT=13 -> PASS (~2.7 TPS short prompt)

## 002b headline 04_logic_bug
- Prior run: PASS=false tool_calls=0 (Agentic QUANT_FATAL then crash/hang)
- Current: Agentic generates text (smoke5 AGENT_DONE) but TinyLlama does not emit tool JSON
- Q6_K attn_v + Q6_K lmHead are expected for Q4_K_M; not a mis-dispatch
- Agentic TPS ~0.1-2 depending on prompt length / logging; tool-heavy prompts are slow

## Invariants so far
demo_break=false
scripted_runtime=false
