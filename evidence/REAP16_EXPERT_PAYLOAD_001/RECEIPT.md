# REAP16 Laguna Expert Payload Integrity — Full Verification

Scope: G02 complete payload verification for the Laguna S2.1 REAP35 export.
Audit only. No model was modified. `PROMOTE=0`.

## Inputs

| Role | Path | Source SHA-256 (first 1 MiB) |
|---|---|---|
| Source | `F:\OllamaModels\blobs\sha256-948255a146c07678678183af4cb1234a124e945e48c85c2006598ef4696552c8` | `200b7025f18b4ccafee6e2af533270549ecbd8a6335669d696a6656806ab7d03` |
| Export | `F:\OllamaModels\_REAP16\laguna-s-2_1-Q4_K_M-REAP35\sha256-948255a146c07678678183af4cb1234a124e945e48c85c2006598ef4696552c8` | `5fb983244dc4a2f0164d448d96fad394b633c0f17866efa4f5a4d4b4a925a902` |

1 MiB prefixes come from `RESULTS_REAP16.json`. They are not full-file digests and are
not claimed as such; full-file SHA-256 is `NOT_RUN` for the 96 GB source.

## Method

Per-tensor `name`, `dims`, `total_bytes`, `abs_offset` obtained from
`tools/gguf_geometry_audit_msvc.exe --json` on both files.

GGUF stores `dims` as `[ne0, ne1, ne2]` with `ne0` contiguous, so the expert axis (`ne2`,
the trailing dim) is the slowest-varying. Each expert therefore occupies one contiguous
byte range of `total_bytes / expert_count`, and the retained experts form one contiguous
prefix block. This was validated empirically: the contiguous-block hashes match, which
would fail if experts were interleaved.

Comparisons are over **encoded** bytes — quant blocks, scales and all — never converted to
floating point.

| Class | Comparison |
|---|---|
| Expert tensors (`*_exps`) | SHA-256 of the whole retained 35-expert block: source `[off, off + 35*slice)` vs export `[off, off + 35*slice)` |
| Expert router / bias | SHA-256 of the export's full payload vs the **same-length prefix** of the source |
| Invariant tensors | SHA-256 of the full tensor in both files |

Range reads are seekable, 8 MiB chunks, so no model is loaded into memory.

## Result

```
LAGUNA_FULL_PAYLOAD
expert_tensors=141      ok=141   bad=0
nonexpert_tensors=673   ok=579   bad=94
bytes_compared=16,757,078,016

LAGUNA_ROUTER_PAYLOAD_PREFIX_CHECK
size_reduced_tensors=94   prefix_match=94   prefix_mismatch=0
  ffn_gate_inp.weight = 47
  exp_probs_b.bias    = 47
```

The 94 "mismatches" in the first pass were a classification error in the checker, not a
defect: `exp_probs_b.bias` (256 to 35 floats) and `ffn_gate_inp.weight` (router matrix,
256 to 35 columns) scale with expert count by design. Re-checked as prefix slices, all 94
match.

## Tensor discovery reconciliation

```
141 expert  +  94 router/bias  +  579 invariant  =  814
```

`814` is exactly the `tensor_count` reported by the geometry audit for this file. Every
tensor in the export is therefore classified, compared and accounted for — the auditor's
discovery rules missed nothing.

## Coverage

| Class | Tensors | Slices / bytes | Result |
|---|---|---|---|
| Expert tensors | 141 | 4,935 expert slices (35 x 141), 16,757,078,016 B | 0 mismatches |
| Router + bias | 94 | 94 payloads | 0 mismatches |
| Invariant | 579 | 579 payloads | 0 mismatches |

## What this establishes

- Every retained expert weight in the export is byte-identical to its source expert.
  All 35 retained experts are covered, not a sample; interior experts included.
- Expert index mapping is the identity: export expert *i* is source expert *i*.
- The router weight and expert bias are correct prefixes of their sources, so routing is
  consistent with the retained expert set.
- Every non-expert tensor is preserved byte-for-byte.
- The export is a lossless prefix truncation, verified end to end.

## What this does NOT establish

- `REAP_QUALITY` is `NOT_RUN`. Byte-identical retained weights do not show that 35 of 256
  experts preserve model behaviour. That is a separate acceptance question.
- `REAP_NATIVE` is `BLOCKED_ON_BUILD`. Nothing here was executed by Deep2.
- Prefix truncation is a valid reduction mechanism but carries no importance criterion. A
  quality benchmark should compare prefix selection against calibrated selection at the
  same retained-expert budget.
- Full-file SHA-256 of the 96 GB source is not computed; only 1 MiB prefixes are recorded.

## Disposition

```
G02_GEOMETRY=PASS
G02_EXPERT_DIM=PASS
G02_EXPERT_PAYLOAD=PASS_FULL_4935_SLICES
G02_ROUTER_PAYLOAD=PASS_94_OF_94
G02_INVARIANT_PAYLOAD=PASS_579_OF_579
G02_DISCOVERY_RECONCILED=814_OF_814
G02_FULL_FILE_SHA=NOT_RUN
REAP_SELECTION=PREFIX_TRUNCATION
REAP_QUALITY=NOT_RUN
REAP_NATIVE=BLOCKED_ON_BUILD
PROMOTE=0
CERTIFIED=0
```