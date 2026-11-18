# WP-01 independent llama.cpp reference

Status: reference build and launch verified; Deep2 comparison is the next gate.

## Identities

```ini
UPSTREAM_REPOSITORY=https://github.com/ggml-org/llama.cpp
UPSTREAM_COMMIT=edec462cc00abebc50610b82ac06c6cde266e5d0
MODEL=F:\\rawrxd\\models\\pdurugyan_qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2_latest.gguf
MODEL_SHA256=9BE227448D319E6A7ACCA8056B71BF7D9A2C6B2811986E6658A9DEDC208D0ADA
REFERENCE_EXE_SHA256=BFACF5DBC5849889771128C535943AB22941F5E7D00164552A5A822BB107A5D7
REFERENCE_LOGITS_SHA256=95F9D7DBDED07D0042117B4DCC500106ECE5F305B3270F7E02F359BC0EBE57E8
KV_TYPE_K=F32
KV_TYPE_V=F32
TOKENS=1,185
VOCAB=248320
LOGIT_FLOATS=496640
REFERENCE_EXIT=0
```

## Isolated build

The pinned checkout and build are under `F:\\rawrxd\\wp01_reference` and are not part of the product tree. The standalone `teacher_forced_logits.exe` links only against the pinned llama.cpp build and launches successfully with the model. The aggregate upstream solution build has an unrelated `llama-server-impl.lib` target failure; it does not affect the completed CPU reference targets used here.

Command used:

```powershell
$env:PATH="F:\\rawrxd\\wp01_reference\\build\\bin\\Release;$env:PATH"
F:\\rawrxd\\wp01_reference\\harness-build\\Release\\teacher_forced_logits.exe `
  F:\\rawrxd\\models\\pdurugyan_qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2_latest.gguf `
  F:\\rawrxd\\wp01_reference\\harness-build\\Release\\reference_logits_f32.bin
```

Observed result: `REFERENCE_OK vocab=248320 tokens=2 bytes=1986560`.

This closes WP-01 reference launch and capture. WP-02 remains open until the captured rows are compared against Deep2 CPU and GPU outputs with matching token positions and predeclared tolerances.
