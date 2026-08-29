DEEP2-PARITY-PROBE-001 — 2026-08-29
branch=cert/deep2-parity-probe-001 (from main 45057c45c; sync tip 994250b32 untouched)

MODEL_MISMATCH_ROOT_CAUSE=
  Earlier PONG `!!` (6824) used F:\~dev\tinyllama_fresh.gguf which loads as **Q4_0**.
  Batch-1 golden UE (4462) used models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf (**Q4_K**).
  Same prompt IDs [21521,9312]; different weight format ? different logits.

Q4_K_M (canonical batch-1 model):
  tokenize_no_bos=[21521,9312] (Deep2 == llama-tokenize --no-bos)
  deep2_greedy_8 = UE, a 19th-  EXPECT=UE PASS
  deep2_greedy_1 = see deep2_q4k_nobos.txt (should be 4462 UE)

Q4_0 tinyllama_fresh:
  deep2_greedy_1 = 6824 `!!` (finite but NOT batch-1 golden)
  Not a regression of Q4_K nibble fix; wrong measuring stick file.

NEXT=
  1) Lock canonical model path to Q4_K_M for all PONG/parity certs
  2) BOS-prefixed parity (llama golden `,`)
  3) Context-length activation sweep on Q4_K_M
  4) Keep sync/cloud-agent-2026-08-29 @ 994250b32 frozen until this cert checkpoint

GATE=parity/context -> logits/content -> PONG(UE) -> AGENT-E2E-002b

CTX_SWEEP_Q4K_M (greedy-1, LAYER_PROBE):
tokens=2 response='UE' peak=LAYER6_POST_FFN:183.26 first_bad=False
tokens=8 response='?PO' peak=LAYER6_POST_FFN:183.26 first_bad=False
tokens=32 response='?PO' peak=LAYER6_POST_FFN:183.26 first_bad=False
