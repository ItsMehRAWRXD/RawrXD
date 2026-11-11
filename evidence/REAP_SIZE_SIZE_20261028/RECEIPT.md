# REAP size/size implementation witness

Timestamp: 2026-10-29T03:55:00Z
Source root: `F:\rawrxd`
Source HEAD before this change set: `0c45ab5cfd`
Promotion: `PROMOTE=0`

This receipt covers the guarded `size/size` implementation and its writer
regression. It does not promote a model reduction without model-specific
calibration, independent parity, quality-floor evidence, and reload evidence.

## Built artifacts

| Artifact | SHA-256 | Result |
|---|---|---|
| `F:\rawrxd\build_ide\bin-msvc\rawr-reap.exe` | `8D41AF8B505E5B31A6BCCF00A70EEA06DA58F5CB3B6FACB3C448852C7AA33A7D` | built |
| `F:\rawrxd\build_ide\bin-msvc\rawr.exe` | `1C4B2DC08C00DC2DBBA2F6FB220827F361CD33C47A8977318CCD239370114F76` | built |
| `F:\rawrxd\build_ide\bin-msvc\rawr-reap-writer.exe` | `BC6A6161E55CCF79084A910A4A296E85B45DD4C1D22687B7C4FCCCDEB972F9A8` | built |
| `F:\rawrxd\build_ide\reap-moe-transform-test.exe` | `E0F76934D22F0806E28CC63E5531ECD497D41051CF83E7015BFA9BAC0535094B` | built |

The frozen product executable was not rebuilt or overwritten.

## Verified behavior

1. `rawr-reap plan` on the 13-shard Kimi K2 model with `--size 30GiB`:
   `PRUNING_CANDIDATE_REQUIRES_CALIBRATION_MASK`, exit `4`.
2. `rawr-reap plan` on dense Phi-3 with `--size 30GiB`:
   `FITS_UNMODIFIED_NO_PRUNING`, exit `0`.
3. `rawr reap` on Qwen3.6-A3B with a 30-GiB target:
   `REAP_MODEL_NOT_IN_INVENTORY`, `transformation_enabled=false`, exit `4`.
4. `reap-moe-transform-test.exe`:
   `REAP_MOE_TRANSFORM_PASS`, `TRANSFORMED_TENSORS=5`, `SOURCE_UNCHANGED=1`,
   `RELOAD_PASS=1`, `TARGET_ENFORCEMENT_PASS=1`, and
   `PARTIAL_OUTPUT_ROLLBACK_PASS=1`, exit `0`.
5. Targeted CTest:
   `rawr_reap_cli_contract`, `rawr_reap_expert_layout`, and
   `reap_moe_transform`: 3/3 passed.
6. `rawr-reap-writer` rebuilt with live byte-for-byte round-trip validation;
   the verification path now returns success after the comparison completes.
7. Unified `rawr reap` accepted `--size 30GiB` as the explicit REAP alias,
   remained correctly blocked at admission with exit `4`, and rejected a
   duplicate `--size` plus `--target-size` request with exit `2`.

## Source corrections covered

- Expert and non-expert tensor copies now read from the source shard's data
  base, not the rebuilt output data base.
- The writer enforces the measured aggregate output size against the requested
  target and removes a newly created candidate directory on any failed write.
- The writer adds a `rawrxd.reap.active_experts` provenance field, forcing the
  rebuilt GGUF header/data offset to be exercised by the fixture.
- The target size now propagates through both the standalone REAP CLI and the
  unified `rawr` pipeline.
- Standalone `reap` accepts the legacy `--size` spelling as an alias for
  `--target-size`, rejects conflicting size flags, and refuses manifests whose
  estimated expert residency or output exceeds the requested budgets.
- Selection manifests carry the evaluated quality-floor gate; rewrite
  authorization requires that gate as well as calibration and parity.
- The parser rejects duplicate `--size`/`--target-size` aliases and trailing
  arguments on `inspect` and `capabilities` instead of ignoring them.
- A deterministic GGUF fixture verifies selected expert/router slices,
  source immutability, reload, inventory preservation, and target rejection.

## Remaining model-specific gates

The Qwen3.6-A3B one-window continuous probe completed with zero generated
tokens and no route metrics, so its calibration remains blocked. No reduced
Qwen, Kimi, DeepSeek, MiniMax, or other model is certified by this receipt.
The production admission gate remains fail-closed until each model supplies
its own calibration, independent reference parity, selection, quality-floor,
writer, reload, and post-reduction inference evidence.
