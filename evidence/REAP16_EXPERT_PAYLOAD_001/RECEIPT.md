# REAP16 Expert Payload Integrity

Scope: G02 retained-tensor payload verification for the Laguna S2.1 REAP35 export.
Audit only. No model was modified. `PROMOTE=0`.

## Inputs

| Role | Path | Source SHA-256 (first 1 MiB) |
|---|---|---|
| Source | `F:\OllamaModels\blobs\sha256-948255a146c07678678183af4cb1234a124e945e48c85c2006598ef4696552c8` | `200b7025f18b4ccafee6e2af533270549ecbd8a6335669d696a6656806ab7d03` |
| Export | `F:\OllamaModels\_REAP16\laguna-s-2_1-Q4_K_M-REAP35\sha256-948255a146c07678678183af4cb1234a124e945e48c85c2006598ef4696552c8` | `5fb983244dc4a2f0164d448d96fad394b633c0f17866efa4f5a4d4b4a925a902` |

1 MiB prefixes are taken from `RESULTS_REAP16.json`; they are not full-file digests and are not claimed as such.

## Method

1. `tools/gguf_geometry_audit_msvc.exe --json` on source and export to obtain, per tensor,
   `name`, `dims`, `total_bytes`, `abs_offset`.
2. Expert count is `dims[last]`. Slice size = `total_bytes / expert_count`.
3. Expert slice *i* occupies `[abs_offset + i*slice, abs_offset + (i+1)*slice)`.
4. SHA-256 of expert slice 0 and of the last retained slice, computed with seekable range reads
   (4 MiB chunks), compared source vs export.

Expert slices are contiguous because the expert dimension is the slowest-varying (`ne2`) axis in
GGUF layout, so slice *i* is a single contiguous byte range in both files.

## Result

```
LAGUNA_EXPERT_PAYLOAD_CHECK
tensors=141
expert0_match=141        expert0_mismatch=0
lastRetained_match=141   lastRetained_mismatch=0
```

Expert count 256 (source) to 35 (export). Last retained index is 34.

## What this establishes

- Every retained expert slice that was sampled is **byte-identical** to its source slice.
  The writer performs a lossless slice-and-copy; retained weights are not requantized,
  rescaled, or otherwise transformed.
- Expert index mapping is the **identity** on retained experts (0 to 0, 34 to 34).
  No permutation is applied. This follows from the selection being a contiguous prefix.
- Combined with the earlier geometry result — all 141 expert tensors reduced from 256 to 35,
  none skipped, with unchanged per-expert row geometry — the export is a structurally and
  payload-consistent truncation.

## What this does NOT establish

- Only 2 of 35 retained expert slices per tensor were hashed (first and last). Interior slices
  are not individually hashed; a defect confined to an interior expert would not be caught.
- Non-expert tensors (attention, norms, SSM state, embeddings) were not payload-checked.
- `REAP_QUALITY` remains `NOT_RUN`. Byte-identical retained weights say nothing about whether
  35 of 256 experts preserve model behaviour; that is a separate acceptance question.
- `REAP_NATIVE` remains `BLOCKED_ON_BUILD`. Nothing here was executed by Deep2.

## Disposition

```
G02_GEOMETRY=PASS
G02_EXPERT_DIM=PASS
G02_EXPERT_PAYLOAD=PASS_SAMPLED_2_OF_35
G02_FULL_PAYLOAD=NOT_RUN
REAP_SELECTION=PREFIX_TRUNCATION
REAP_QUALITY=NOT_RUN
REAP_NATIVE=BLOCKED_ON_BUILD
PROMOTE=0
CERTIFIED=0
```