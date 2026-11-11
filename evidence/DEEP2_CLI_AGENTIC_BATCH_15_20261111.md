# Deep2 CLI agentic batch 15 evidence

- Repository: `F:\rawrxd`
- Branch: `upload/ide-fixes-20261111`
- Baseline: `13e3a05d70bbb47e574f40eb7352a772afafc5cb`
- Tested/committed revision: `8d1f906809`
- Commit: `Fix Deep2 logits boundaries and autonomous CLI input`

## Changes exercised

1. Corrected the ElasticResidencyManager GGUF type mapping to use canonical
   `GGMLType` IDs, including Q2_K/Q3_K/Q4_K/Q5_K/Q6_K.
2. Accepted `token_embeddings.weight` as an embedding alias in single-shard,
   BP16, and multishard loading paths.
3. Added fail-closed `LM_HEAD_GEOMETRY_MISMATCH` diagnostics before `LinearW`.
4. Added `rawr run` support for `--mode=`, `--backend=`, `--prompt=`,
   `--goal=`, `--task=`, and `--max-tokens=` forms.
5. Redirected stdin is now treated as a one-shot goal instead of entering the
   interactive REPL.

## Commands and results

- `cmd.exe /d /s /c 'call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Auxiliary\\Build\\vcvars64.bat" && cmake --build build_ide --config Release --target RawrXD-CLI-V2 -j 2'`
  - PASS: `build_ide\\bin-msvc\\rawr.exe` linked.
- Missing-model parser smoke with `--mode=ask --prompt=... --max-tokens=1 --json`
  - PASS: emitted `RUN_CONFIG_MAX_TOKENS=1` and rejected the missing model;
    no interactive prompt was entered.
- Redirected-stdin smoke with `goal | rawr run ... --mode=ask --max-tokens=1`
  - PASS: emitted the same missing-model error without entering the REPL.
- Real runtime:
  `rawr run llama3.2-3b-Q2_K.gguf --mode=ask --prompt="Say exactly: DEEP2_B15_OK" --max-tokens=1 --json`
  - PASS: model loaded, one Vulkan device opened, prefill and one decode token
    completed, and process exited 0.
  - FAIL: generated token was `<<` (ID 1134), not `DEEP2_B15_OK`.
  - FAIL/OPEN: `DEEP2_GPU_FORWARD_LAYERS=0`, `DEEP2_REAL_GPU_FORWARD=0`, and
    `DEEP2_GPU_FORWARD_FALLBACKS=1` remained in the observed runtime.

## Supplied GUI artifact disposition

`evidence/IDE_RELEASE_READINESS_001/bottom_panels_20261111/RawrXD-PanelFixed.exe`
was verified as a separate 64-bit Windows GUI-subsystem executable:

- SHA-256: `A3BB65AD6794FE92F9693F44D07A0CF1F333817512DC27526B3D6E8FB9CF36B9`
- Size: `3,067,392` bytes
- Launch probe: stayed alive with `--help`; visual inspection exposed the
  `RawrXD IDE` editor, terminal, chat, model controls, and bottom panels.
- It is not the CLI build path. The tested CLI is the CMake target
  `build_ide\\bin-msvc\\rawr.exe` (Windows CUI subsystem).

## Certification disposition

This receipt does not promote certification. Deep2 output correctness remains
open; GPU forward remains unverified/failed for this runtime; Strata/Ollama
agentic generation, SNAP tool calls, and GUI end-to-end token verification were
not claimed by this batch.
