# DEEP2_QWEN2_CPU_CORRECTNESS_001 — Position-0 Single-Token Parity (FIRST MISMATCH FOUND)

Date: 2026-09-28 · Harness: rawrxd_real_gguf_parity.exe (built 0 errors this session)
Model: F:\~dev\qwen2.5-coder-1.5b-base.gguf (qwen2, 28L, H=1536, heads=12, kv=2, V=151936)
Oracle: Ollama 0.34.4 qwen2.5-coder:1.5b-base, raw=true, temp=0, seed=1, greedy-pinned

## Gate ladder result

```
GATE=DEEP2_QWEN2_CPU_CORRECTNESS_001

MODEL_LOAD=PASS               (338 tensors mapped, geometry complete)
TENSOR_BINDINGS_COMPLETE=PASS (arch=qwen2 branch taken, ROPE_ARCH=qwen2, theta=1e6)
LM_HEAD_BINDING_VALID=PASS    (computeLogits ran, 151936 logits)

NTOK1_POS0=PASS               (prompt 'hi' -> 1 token; single forward)
LAYER0_REFERENCE_PARITY=PARTIAL (CPU reference completed; Vulkan replay crashed device-loss — see below)
RMSNORM_REFERENCE_PARITY=?
Q/K/V/O_GEMV_REFERENCE_PARITY=?
FFN_REFERENCE_PARITY=?
LM_HEAD_REFERENCE_PARITY=?

ALL_LAYERS_FINITE=PASS        (golden logits finite: min=-16.7212 max=+11.6988)
LOGITS_FINITE=PASS            (151936 finite)
TOP1_REFERENCE_PARITY=FAIL    <- THE MISMATCH
MULTI_TOKEN_STABLE=?
COHERENT_OUTPUT=FAIL          (engine emits digit-token soup; oracle emits coherent text)

VERDICT=FAIL (first mismatch identified)
```

## THE FIRST MISMATCH: TOKENIZER ENCODE (position 0, single token)

- Engine golden (captured pre-GPU-crash, `_parity_golden_p0.bin`):
  - PROMPT=[hi] → PROMPT_TOKENS=[6023]; STEP0_TOP1=15
  - Vocab decode (authoritative GGUF read): **6023 = "12052"** (digit token!)
  - TOP10 predictions = all digit strings: 15='36', 284='574', 18='42',
    16='38', 304='614', 24='54', 20613='41232', 21='48', 19='44', 1733='3472'
- Reference (ollama, identical weights, raw mode, greedy-pinned):
  - PEVAL=1, EVAL=6 → text "客户服务经理在客户关系管理" (coherent continuation)
- Conclusion: the engine's BPETokenizer encode path (qwen2 = GPT2-style byte-level
  BPE per `tokenizer.ggml.model = gpt2`) is producing WRONG token IDs for plain
  text — 'hi' should map to a text token (not the byte-level digit token 6023='12052').
  Wrong embed row → wrong logits at position 0 → everything downstream diverges.
  This matches the 32B symptom class (punctuation/special token collapse).

## Harness infrastructure fixed to make this measurable

- Wired `rawrxd_real_gguf_parity` CMake target (InferenceEngine link, bin/Release).
- Added missing `main()` forwarding to `RunRealGgufParityCli`.
- Fixed 4MiB stack-buffer overflow (0xC00000FD) in `hashFile` → thread_local heap.
- Golden format reverse-engineered (u32 ver + u32 endian tag + u64-len strings)
  and parsed via Python; CPU reference pass **completes** and writes the golden
  even though the Vulkan replay then hits a device loss in BEGIN_CMD_ALLOC
  (separate engine issue — CPU-side parity authority is usable NOW).

## Next engineering steps (in order)

1. Fix `BPETokenizer::encodeGPT2` for qwen2: GPT-2 byte-level BPE requires
   byte-to-unicode mapping (Ġ encoding) + merges application — verify merges
   table is loaded from `tokenizer.ggml.merges` for Kind::GPT2BPE and that
   pre-tokenization regex matches GPT-2 pattern.
2. Re-run position-0 ladder; expect prompt token for 'hi' to change; compare
   top1 against oracle (ollama raw).
3. THEN descend the operator ladder (embed→rms→Q/K/V→...→lm_head) using the
   checkpoint traces; Vulkan device-loss crash (BEGIN_CMD_ALLOC after LM-head
   upload) is the second blocker, after tokenizer.
4. Only after parity: GPU/TPS work.

Artifacts: `_parity_golden_p0.bin` (CPU golden, position-0), `_golden_final.txt`
(parsed logits), `_vocab_decode_result.txt` (token id→text), receipt schema above.
OLLAMA_CALLS=1 (oracle only). STUB_FALLBACKS=0.