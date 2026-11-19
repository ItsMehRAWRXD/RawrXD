# CPU/GPU Numerical Divergence — First Analysis

Audit only. No model modified. `PROMOTE=0`.

## Inputs

| Item | Value |
|---|---|
| Model | `F:\OllamaModels\_REAP16\Qwen3_6-35B-A3B-GGUF-REAP199\Qwen3.6-35B-A3B-Q4_K_M.gguf` |
| Model bytes | 16,805,500,768 |
| Bench exe | `F:\rawrxd\build_reap\bin\deep2_bench_tps.exe` |
| Bench SHA-256 | `9FE14278495F792BC532B5C3C0D7FD90AAD0D85BD5A570A1C5711BD8B498803E` |
| Prompt tokens | `1 185` |
| Vocab | 248,320 |
| Dump | `--dump-logits`, raw float32 per position, `d2_logits_pos<N>.bin`, 993,280 B each |

Both runs used the identical model file, prompt tokens, position order, and
`--serial-prefill --no-batch`. Only the backend differed: `--cpu` versus the Vulkan path.

## Measured logits comparison

| Pos | Differing elems | Max abs | RMS | CPU argmax | GPU argmax |
|---|---|---|---|---|---|
| 0 | 248320 / 248320 | 3.092007 | 0.593119 | 110817 | 110817 |
| 1 | 248320 / 248320 | 1.018500 | 0.176842 | 5024 | 9022 |
| 2 | 248320 / 248320 | 11.127852 | 2.094439 | 1686 | 322 |

Position 2 is not an independent sample: the decode loop feeds the previously
generated token, so once positions 0/1 disagree, position 2 receives a different
input. Its larger error is a consequence, not a second defect.

## Top-5 logits

```
pos0 CPU: 110817=9.7923  160231=8.6703  15560=8.5340  110296=8.3932  96106=8.3353
pos0 GPU: 110817=10.2114 160231=9.2024  112973=9.0029 91664=8.7140  86174=8.6888

pos1 CPU: 5024=8.5823  9022=8.5616  146030=8.3806  114425=7.7662  9241=7.5749
pos1 GPU: 9022=8.8316  5024=8.4058  146030=7.9699  114425=7.9138  9241=7.8011
```

## Analysis

**Position 0 agrees on the argmax.** Both paths select token 110817, and both rank
160231 second. The top-1 margin is 1.122 (CPU) and 1.009 (GPU). The GPU logits are
offset upward on the leading tokens by roughly 0.42 to 0.47, and the ordering of
ranks 3 to 5 differs, but that cluster spans only 8.33 to 8.71 and is dense enough
that reordering under a perturbation of this size is expected.

**Position 1 is a near-tie.** The CPU top-2 margin is

```
5024 = 8.5823
9022 = 8.5616
margin = 0.0207
```

The GPU ranks 9022 first at 8.8316 with 5024 at 8.4058, a margin of 0.4258 in the
opposite direction. A numerical difference of the size already present at position 0
is roughly twenty times larger than the position-1 top-2 margin, so the argmax flip
follows arithmetically from accumulated numerical difference. No discrete logic
error is required to explain it.

## Conclusion

The divergence is **numerical, not logical**. Both paths are self-consistent; they
differ because the Vulkan quant-dot kernels and the CPU reference recurrence
accumulate in different orders and round differently. Every one of the 248,320
logits differs at every position, which is the signature of a different arithmetic
path rather than a single faulty operation.

**Which path is correct is not established by this comparison.** CPU/GPU agreement
alone would not settle it, and disagreement does not identify a culprit. The
tie-break requires an independent reference on the identical GGUF and input.

## Next steps

1. Run `F:\llama.cpp-ref\build\bin\llama-cli.exe` (reports `qwen35moe` support) on
   the same reduced GGUF with the same prompt and greedy settings, and compare its
   first-position logits and first token against both RawrXD paths. That is the only
   way to assign correctness rather than merely difference.
2. If the reference agrees with the CPU path, the Vulkan kernels are the suspect and
   the next step is a per-op comparison inside the GPU path.
3. If it agrees with the GPU path, the CPU reference recurrence is the suspect.
4. Re-run with a prompt whose position-1 top-2 margin is wide, so that ordinary
   numerical noise cannot flip the argmax and the comparison measures computation
   rather than a coin flip.
5. Batch-boundary matrix (31/32/33/64/65/192/199/200) remains untested and separate.

## Disposition

```
PARITY_MODEL_BYTES=16805500768
PARITY_EXE_SHA=9FE14278495F792BC532B5C3C0D7FD90AAD0D85BD5A570A1C5711BD8B498803E
PARITY_INPUT_TOKENS=1_185
PARITY_POS=0
PARITY_VOCAB=248320

CPU_GPU_MAX_ABS_POS0=3.092007
CPU_GPU_RMS_POS0=0.593119
CPU_ARGMAX_POS0=110817
GPU_ARGMAX_POS0=110817
CPU_ARGMAX_POS1=5024
GPU_ARGMAX_POS1=9022
POS1_TOP2_MARGIN_CPU=0.0207

DIVERGENCE_CLASS=NUMERICAL_NOT_LOGICAL
FIRST_DIVERGENT_OP=NOT_ISOLATED
CORRECT_PATH=UNDETERMINED
INDEPENDENT_REFERENCE=NOT_RUN
PARITY_VERDICT=FAIL

PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```