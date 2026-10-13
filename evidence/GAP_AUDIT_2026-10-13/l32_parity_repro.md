# Parity repro artifacts (llama3.2:3b, tokens [1 185], 2026-10-13)

Reproducer chain (rerun order):

1. Reference dump (llama.cpp c479922a, default F16 KV cache):
   llama_dump_internals.exe <gguf> tokens.txt ref 128256
2. Deep2 dump:
   tools\deep2_parity_trace.exe --model <gguf> --tokens "1 185" --outdir d2
3. Comparator: l32_20261013\..\l32 per-occurrence mapping:
   - ref node naming: ds_<pos>_<name>-<layer>_occ<N>.bin (N = graph occurrence)
   - Qcur/Kcur occ0/occ1 are PRE-rope (match Deep2's dumps at cos 1.000000);
     occ2 / "(view)" / "(view) (permuted)" are post-rope.
   - kqv_out = pre-wo attention output (post-wo is named attn_out).

Defects found and fixed in this session:

A. RoPE pairing (runtime_graph_executor.cpp, OpAttention):
   llama-family got NEOX split-half pairing; llama.cpp's LLAMA rope is NORM
   (adjacent pairs). Fixed by following the llama.cpp LLAMA_ROPE_TYPE table.
   Evidence: pos-1 blk00 q/k raw cos 1.000000; post-rope reconstruction with
   NORM reproduces reference Qcur/Kcur at cos 0.99999994/0.99999996; attention
   output went from cos 0.9843 to 0.9999997; pos-1 argmax 12942 -> 26957 (== ref).

B. KV cache precision (runtime_graph_executor.cpp, cache write):
   llama.cpp stores K/V as F16 by default. Reference kqv_out is BIT-EXACTLY
   F16(Vcur) (rel 0.0 vs 3.345e-4 for F32). Deep2 now rounds on write
   (DEEP2_KV_F32=1 keeps diagnostics). pos-0 logits cos 0.99887 -> 0.99993.

C. Resource-governed KV growth (RAWRXD_RESOURCE_GOVERNOR_001): KV growth is
   lease-admitted; DEEP2_KV_BUDGET_MB=1 fails closed at block 16 position 4
   with "kv cache growth rejected by resource governor", exit 1. No silent
   truncation.

Final numbers: pos0 logits cos 0.999928061 (argmax 2 vs 791, 0.0073 near-tie),
pos1 cos 0.996919727 (argmax MATCHES 26957). Per-op tolerance table in
l32_per_op_tolerances.json. Remaining divergence is Q8_K quantization-boundary
sensitivity: Deep2 dot == llama.cpp dot to 2.2e-7 on blk00/05 (float-dequant
isolation), inputs differing ~1e-6 flip individual q8 boundaries, dot outputs
differ ~1e-3 and the residual stream amplifies it to the bounded table values.
