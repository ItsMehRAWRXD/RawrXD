# DEEP2 one-token / PONG smoke — updated 2026-08-29 (batch-1)

## Result

**PASS vs llama.cpp** for prompt `PONG` without BOS.

- Deep2 greedy-1: token **4462** (`UE`)
- llama.cpp greedy-1 (same tokenize): **`UE`**
- Prior `EXPECT_CONTAINS=PONG` was a bad golden (exit 2); use `UE`.

## Fix landed

Q4_K dequant/GEMV nibble packing corrected to ggml layout (see `evidence/DEEP2_PONG_BATCH1/`).

## Chain position

```
load → one-token forward → finite → correct greedy (no-BOS PONG) ✓
→ multi-token ✓ (8-tok matched)
→ tool-call synthesis → AGENT-E2E-002b
```
