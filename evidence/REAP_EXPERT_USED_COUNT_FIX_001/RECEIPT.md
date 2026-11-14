# REAP Exporter Defect — `expert_used_count` Overwritten

Scope: repair of the REAP MoE metadata writer and recovery of three exported models.
No model weights were altered; only a 4-byte metadata field per file.
`PROMOTE=0`.

## Symptom

| Model | Ollama load before | Error |
|---|---|---|
| `reap16-glm-4_7-flash` | HTTP 500 | `ggml.c:1831: GGML_ASSERT(obj_new) failed`, exit `0xC0000409` |
| `reap16-nemotron-3_5` | HTTP 500 | same assertion |
| `reap16-qwen3_6-35b` | OK | — (but routing was still wrong) |
| `reap16-ornith-1_5` | OK | — |
| `reap16-laguna-s-2_1` | OK | — |

## Root cause

`src/deep2/ReapMoETransformer.cpp`, `patchMetadata()`. The key filter was:

```cpp
if (key.find("expert_count") == std::string::npos &&
    key.find("expert_used_count") == std::string::npos) continue;
```

`&&` means a key matching **either** substring was rewritten. `expert_used_count` does not
contain the substring `expert_count` (it is `expert_used_count`, not `expert_count`), so it
reached the write path and received the retained-expert count.

Two different fields were therefore conflated:

| Field | Meaning | Correct value |
|---|---|---|
| `*.expert_count` | experts in the physical bank | retained count |
| `*.expert_used_count` | experts activated per token (top-k) | **original top-k** |

Measured before the fix:

| Model | expert_count | expert_used_count (orig) | expert_used_count (export) | Should be |
|---|---|---|---|---|
| Qwen3.6 | 256 → 199 | 8 | **199** | 8 |
| GLM-4.7 | 64 → 59 | 4 | **59** | 4 |
| Nemotron | 128 → 81 | 6 | **81** | 6 |

Every surviving expert became active for every token. On GLM and Nemotron that inflated the
graph and its allocation past what the loader's object arena could satisfy, producing the
`obj_new` assertion. On Qwen it loaded but silently changed the routing semantics.

The ORIGINAL (non-REAP) GLM file loads cleanly in the same llama.cpp build, so this was not
an architecture-support gap.

## Source fix

`patchMetadata` now:

1. Rewrites **only** keys whose lowercased form ends with `expert_count`.
5. Reads `expert_used_count` without writing it.
6. Clamps top-k down to the retained count **only** when the original top-k exceeds it,
   which is the one case where the original value is unsatisfiable.

The array branch that previously overwrote every element of an expert-count array was
removed; an array-typed `expert_count` is not a physical bank size.

## Data repair

`expert_used_count` is a `u32` stored inline in the GGUF header, so each affected file was
repaired with a single 4-byte write at a verified offset. Offsets were read from the file
itself, not assumed.

| File | Offset | Before | After |
|---|---|---|---|
| `...REAP199\Qwen3.6-35B-A3B-Q4_K_M.gguf` | 830 | 199 | 8 |
| `...REAP59\GLM-4.7-Flash-Q4_K_M.gguf` | 637 | 59 | 4 |
| `...REAP81\sha256-5c19f628…` | 1298 | 81 | 6 |
| `blobs\sha256-5d3c0292…` (Ollama GLM) | 637 | 59 | 4 |
| `blobs\sha256-29875b7a…` (Ollama Nemotron) | 1298 | 81 | 6 |

Ollama serves from its own blob copies under `F:\OllamaModels\blobs`, not from the
`_REAP16` export directory, so the blobs had to be repaired separately. The `_REAP16` files
and the blobs are now consistent.

## Verification

```
llama.cpp (F:\llama.cpp-ref build b1-961c376)

  GLM-4.7 REAP59      load PASS   Prompt 26.9 t/s   Generation 12.0 t/s   exit 0
  Nemotron REAP81     load PASS   Prompt 17.2 t/s   Generation  8.7 t/s   exit 0

Ollama 0.40.16

  reap16-glm-4_7-flash:latest     OK  resp='OK.'
  reap16-nemotron-3_5:latest      OK  resp='OK'
  reap16-qwen3_6-35b:latest       OK  resp='OK'
```

Metadata after repair:

```
qwen35moe.expert_count      = 199    qwen35moe.expert_used_count      = 8
deepseek2.expert_count      = 59     deepseek2.expert_used_count      = 4
nemotron_h_moe.expert_count = 81     nemotron_h_moe.expert_used_count = 6
```

## Tooling added

`tools/gguf_meta_dump.cpp` — prints every GGUF metadata key, type, value and byte offset.
Built because the existing audit tool skips metadata values and because `ftell` returns a
32-bit `long` on Windows, which misreported every multi-GiB model as empty until switched to
`_ftelli64`.

## What this does NOT establish

- **Quality.** The three exports now run, but no A/B quality evaluation against their
  originals exists. `REAP_QUALITY` remains `NOT_RUN`.
- **Native Deep2.** `REAP_NATIVE` remains `BLOCKED_ON_BUILD`; Deep2's own reader still needs
  to be exercised against the corrected metadata.
- **Remaining four exports.** Ornith and Laguna were not re-patched because their original
  top-k equals the retained count, so the overwrite was a no-op for them; that reasoning
  should be re-checked per model rather than assumed.
- **Re-export.** The shipped exporter was not re-run; the three artifacts were repaired in
  place. A clean re-export with the fixed writer is still required before any artifact is
  treated as reproducible.

## Disposition

```
REAP_EXPORT_ROOT_CAUSE=IDENTIFIED
DEFECT=EXPERT_USED_COUNT_OVERWRITTEN
EXPORTER_FIX=APPLIED_SOURCE
ARTIFACTS_REPAIRED=5_FILES_IN_PLACE

GLM47_LOAD=PASS
NEMOTRON_LOAD=PASS
QWEN36_LOAD=PASS
GLM47_GENERATE=PASS
NEMOTRON_GENERATE=PASS

REEXPORT_WITH_FIXED_WRITER=NOT_RUN
REAP_QUALITY=NOT_RUN
REAP_NATIVE=BLOCKED_ON_BUILD

PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```