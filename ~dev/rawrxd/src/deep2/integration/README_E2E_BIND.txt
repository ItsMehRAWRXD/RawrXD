DEEP2 BATCH 76-80 — INDEPENDENT REAL-MODEL E2E AUDIT — NO THIRD-PARTY DEPENDENCIES

GOAL
The product may emit facts, but it never mints its own E2E PASS. The separate
`deep2_e2e_audit.exe` reopens and hashes every recorded GGUF/shard, replays the
trace, verifies exact token/output lineage, and then mints PASS/HOLD.

B76 MODEL PROVENANCE
- Construct E2ETraceWriter at the real `rawr run` entry point.
- Pass every GGUF/shard actually used by the model to `open(...)`.
- Writer SHA-256s them; auditor independently SHA-256s them again.
- Auditor also verifies each file begins with GGUF and has a supported version.
- Call discover() only after the real model resolver found the model.
- Call opened() only after the actual loader successfully opened/mapped it.

B77 TOKEN LINEAGE
- tokenized(real_prompt_count) after production tokenizer returns IDs.
- sample(tok,id) at the real sampler decision.
- detokenize(tok,id,bytes,n) with exact bytes returned by production detokenizer.
- Write those exact bytes to stdout.
- stream(tok,id,bytes,n) ONLY after the stdout write succeeds.
- Run `rawr run ... > captured.stdout`; the external auditor requires the
  concatenated STREAM bytes to be byte-for-byte identical to captured stdout.

B78 FULL LAYER / KV / LOGITS
- forward(tok,layer) at the real transformer block execution site.
- Every layer 0..layers-1 must appear for every emitted token.
- kv(tok[,layer]) at real KV mutation/commit; at least one is required per token.
- logits(tok,vocab_size) only when the real final vocabulary logits row exists.
- The auditor requires LOGITS -> SAMPLE -> DETOKENIZE -> STREAM ordering.

B79 NO SUBSTITUTION
- backend() only after the Deep2 backend is selected.
- synthetic(tok) if any token comes from a canned/precomputed/test path.
- proxy() before any Ollama/HTTP/remote inference call.
- fallback() before any alternate inference backend is entered.
- Any SYNTHETIC/PROXY/FALLBACK event makes B79 HOLD.

B80 INDEPENDENT REPLAY
- end() at normal product completion.
- The trace intentionally contains NO product PASS bit.
- Only `deep2_e2e_audit.exe` produces DEEP2_REAL_MODEL_E2E=PASS.

WEIGHT AUTHORITY
Call weight_touch(bytes) from the actual tensor reader/mmap page-touch/upload path.
Do not call it from a benchmark wrapper. B80 requires non-zero real weight traffic.

RECOMMENDED REAL RUN
1) Set your engine's audit trace path to e.g. runs\real_e2e.trace and bind a writer.
2) Capture clean product output:
     rawr run <real-model> "Introduce yourself in under 99 words" > runs\real_e2e.stdout
3) Independently audit:
     deep2_e2e_audit.exe --trace runs\real_e2e.trace --stdout runs\real_e2e.stdout
4) Promote only if all B76..B80 are PASS and DEEP2_REAL_MODEL_E2E=PASS.

IMPORTANT
The included selftest uses a tiny GGUF-shaped fixture only to test the AUDITOR.
It is explicitly NOT a real-model inference proof and must never be promoted as one.
