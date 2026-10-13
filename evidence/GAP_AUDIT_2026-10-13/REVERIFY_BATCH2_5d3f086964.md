# Re-Verification Batch 2 at HEAD `5d3f086964`: Gates 1 (toolchain) and 3

Date: 2026-10-13. Source revision: `5d3f086964` (git rev-parse HEAD).

## Gate 3 — GGUF geometry and tensor type authority: RE-VERIFIED PASS

Command: `tools\deep2_universal_ingest.exe <llama3.2-3b-Q4_K.gguf>`,
exit 0, `VERDICT=PASS`. The type table is sourced from the authoritative
`ggml.h` (the earlier type-mismatch errors are gone); every tensor family
round-trips its dequantization path (`q4_K x3861 ok`, `q6_K x790 ok`,
`q8_0 x732 ok`, `bf16 x642 ok`, `iq* ok`, `mxfp4 x182 ok`, ...). Geometry is
therefore certified from the authoritative header at this revision.

## Gate 1 — build: PARTIAL RE-VERIFICATION (honest scope)

Certification-toolchain builds re-run at this revision, both exit 0:

- `tools\build_deep2_parity_trace.bat` -> `Built: tools\deep2_parity_trace.exe` (exit 0)
- `_eval_harness`/`src\build_rawr.bat` -> `RAWREXE_RC=0` (bin\rawr.exe)

These compile the Deep2 executor, universal GGUF ingest, quant-dot dispatch,
Vulkan compute and the universal-agent stack that the gates certify. The
**full top-level CMake configure+build** was not re-run in this batch (it was
last certified at `a551012de`) and is explicitly NOT promoted: it remains the
one open item in this re-verification batch.

## Position in the ledger

| Gate | Status after this batch |
|------|--------------------------|
| 1 — build | Toolchain builds re-verified PASS at `5d3f086964`; full CMake build NOT re-run (open) |
| 2 — primitive provenance | Open |
| 3 — GGUF geometry | Re-verified PASS at `5d3f086964` |
| 4 — native CPU/GPU forward | Re-verified PASS at `1b43b36a54` |
| 5 — full-logit parity | Open |
| 6 — multi-token KV | Re-verified PASS at `1b43b36a54` |
| 7 — production performance | Open |
