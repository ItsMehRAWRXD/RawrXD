# D1 Batched Prefill Acceptance Receipt

- Branch: `codex/d1-batched-prefill`
- Base commit: `d09d513a2d53da2290ca2b99e18c83cd4b9bc4c8`
- Implementation commit: `1413e2c3a9e9117594be9596c5eceefb9a694a25`
- Evidence commit: `bf3979546b7cf5ced1abd4c4be01388f586b058c`
- Build command: `tools/build_d1_prefill_verify.bat`
- Build result: `D1_BUILD_RC=0`
- Model: `F:\rawrxd\gemma3-1b-Q2_K.gguf`
- Backend: CPU reference (`--gpu` omitted)
- Token fixture: deterministic IDs `1..128`

## Correctness Matrix

All required lengths passed with bit-exact logits, equal KV footprints, bit-exact split continuation, and zero nonfinite logits:

`1 PASS`, `2 PASS`, `8 PASS`, `32 PASS`, `128 PASS`

Overall result: `D1_RESULT: PASS`
