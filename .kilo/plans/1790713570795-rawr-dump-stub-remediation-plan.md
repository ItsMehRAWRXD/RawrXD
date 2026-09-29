# RawrXD: implement the dump chain for real, then reboot

## Decision (locked)

Retract `RAWRXD_RAWR_DUMP_AUTHORITY_001=PASS` to `UNIMPLEMENTED_STUB`, implement the dump
chain against the real filesystem, and only then run the reboot persistence gate.

The build work stays closed and is not redone: the 10 dump sources compile, link, and run.
What never happened is the catalog *implementation*.

## Why the PASS is being retracted

`rawr dump --format receipt` prints `VERDICT=PASS` unconditionally.

`src/cli/RawrDumpAuthority.cpp`
- `:92-97` — every count is a literal (`modelsDiscovered = 161`, `:92` commented
  `// Example: from Ollama models root`).
- `:100-104` — verdict derived from those literals.
- `:128-131` — the `--all` table is 4 hardcoded rows; this is the origin of the
  `RAWR_DUMP_MODEL_COUNT=4` figure.
- `:37-40` — scan counters initialized to 0, never assigned, so the receipt truthfully
  prints `ROOTS_SCANNED=0 … GGUF_FILES_SCANNED=0` beside `MODELS_DISCOVERED=161`.
- `:112` and `:118` — duplicate `writeDumpReceipt()` call; receipt prints twice.

Same pattern elsewhere in the chain:
- `src/models/ModelCatalogAuthority.cpp:81-117` — `scanModelRoots()` pushes 6 literal
  paths with no directory enumeration; aliases/manifests/gguf likewise. `:120-123` and
  `:135-138` only print. `modelsDiscovered` is never assigned, so this path would FAIL;
  `RawrDumpAuthority` never calls it.
- `src/models/GgufMetadataProbe.cpp:44-58` — `// Simulate GGUF metadata probing`,
  `sha256 = "abc123def456..."`, all fields literal.
- `src/cli/RawrRunWildcardAuthority.cpp:37-44` — `// Simplified example`,
  `generatedTokenCount = 42`, `verdict = "PASS"`.

Unrelated and **valid**, do not touch: `RAWRXD_INSTALLED_BINARY_TRUTH_001=PASS_PRE_REBOOT`
(SHA256 `6BD67BF6…321C` on both binaries; registry User PATH contains
`C:\Users\Garrett\rawrxd\bin`; the earlier empty `Get-Command` was stale process env).

## Corrected ledger

```text
RAWRXD_RAWR_DUMP_AUTHORITY_001=UNIMPLEMENTED_STUB   (retracted from PASS)
RAWRXD_MODEL_CATALOG_AUTHORITY_001=UNIMPLEMENTED_STUB
RAWRXD_GGUF_METADATA_PROBE_001=UNIMPLEMENTED_STUB
RAWRXD_RAWR_RUN_WILDCARD_AUTHORITY_001=UNIMPLEMENTED_STUB
RAWRXD_INSTALLED_BINARY_TRUTH_001=PASS_PRE_REBOOT   (valid)
RAWRXD_REBOOT_PERSISTENCE_AUTHORITY_001=PENDING
```

## Task 1 — Retract the fabricated receipts (do this first)

- Do **not** write `_rawr_dump_authority_receipt.txt` with `VERDICT=PASS`.
- If one already exists containing `MODELS_DISCOVERED=161` or `RAWR_DUMP_MODEL_COUNT=4`,
  replace it with `VERDICT=FAIL` and a `STUB_EVIDENCE=` list of the file:line references above.
- Amend the message on `f49f425e5` so it does not claim the dump gate passed. Do not
  rewrite history — note the correction in the next commit.

## Task 2 — Real GGUF header probe

Rewrite `probeGgufMetadata()` in `src/models/GgufMetadataProbe.cpp`.

- Reuse existing real machinery where possible: `src/core/analyzer_distiller.h:23-24`
  (`AD_GGUFHeader`, magic `0x46554747666C6C67`) and `:76-79` (`AD_OpenGGUFFile`,
  `AD_ValidateGGUFHeader`). Do not hand-roll a second parser if these are linkable from
  the `rawr` target; check linkage first.
- Otherwise read a minimal header directly: magic (`GGUF`), `version`, `tensor_count`,
  `metadata_kv_count`, then walk the KV block for `general.architecture` and
  `general.name`. Confirm the KV value-type enum and array layout against the GGUF
  spec before coding — a wrong type table silently desynchronizes the walk.
- Derive `fileSizeBytes` from the actual file; compute a real `sha256` (or drop the field
  rather than emit a placeholder).
- `valid` must reflect magic/version match; `verdict` must derive from `valid`.
- Replace the single-value `g_ggufState` global with per-path results so
  `probeAllGgufMetadata()` can return one record per model.

## Task 3 — Real directory and manifest scanning

In `src/models/ModelCatalogAuthority.cpp`:

- `scanModelRoots()` (`:81-90`) — expand `%VAR%`/`%USERPROFILE%`, check existence with
  `std::filesystem`, enumerate recursively for `.gguf`. Drop roots that do not exist and
  report them as skipped.
- `scanOllamaManifests()` (`:102-108`) — parse real manifest files and resolve blob
  digests to blob paths. Note `rawrxd_run_modelname_001.cpp:123,210` already implements
  Ollama reference→blob resolution; mirror that rather than inventing a second method.
- `scanLocalGguf()` (`:111-117`) — enumerate `.gguf` files.
- `scanAliases()` (`:93-99`) — parse the real alias files. The lookup order and file
  format (`alias = value`, `#` comments) are already documented at
  `rawrxd_run_modelname_001.cpp:36-41`.
- `dedupeModelRecords()` (`:120-123`) and `applyUserDumpRules()` (`:135-138`) — implement
  real dedup by resolved path; apply `RawrDumpRules` for real.
- Assign `modelsDiscovered` from the actual scan result. **It must be 0 when no roots
  exist** — the hardcoded 161 must become an observation.

## Task 4 — Wire the CLI to the real catalog

In `src/cli/RawrDumpAuthority.cpp`:

- Replace `:92-97` with a call to `buildCatalogFromScratch()` and report its real counters.
- Delete the duplicate `writeDumpReceipt()` at `:118`; keep the format-specific call at `:112`.
- Replace `writeTableDump()` (`:128-131`), `writeJsonDump()` (`:144-169`) and
  `writeMarkdownDump()` (`:177`) with iteration over real records. `--all` must list every
  discovered model, not 4.
- Make the `--out` flag (`:78-81`) actually write to `g_dumpState.outputPath`; it is
  currently parsed and ignored (`OUTPUT_PATH=` prints empty).
- Extend `RawrDumpAuthority.h` with a record type; the current header exposes only
  free functions and no state accessor, which is why the output had to be hardcoded.

## Task 5 — Reboot verifier, with the stub condition removed

Write `F:\~dev\verify_rawr_after_reboot.ps1` to gate **only** on real things:

- `PATH_RESOLVES_RAWR=1` via `Get-Command rawr` in a genuinely fresh process.
- `RAWRXD_MODEL_DIR` — **verify it is actually set first**. It was never confirmed. If
  unset, either set it before reboot or drop `MODEL_DIR_EXISTS` as a pass condition
  rather than letting it fail for an unrelated reason.
- Real generation via `rawr run` — use the documented flag order
  (`rawr run [--tokens N] [--vulkan] <model> <prompt>`, `src/deep2/rawr_run.cpp:2,19`)
  with a model that genuinely exists. Discover it with `rawr list`; do not hardcode
  `F:\~dev\qwen2.5-coder-1.5b-base.gguf` (existence unverified).
- Assert `GENERATED_TOKEN_COUNT>0` from the real run path.
- **Exclude** `rawr dump --format receipt` as a pass condition. After Task 4 it may be
  re-added, but only on an invariant that would fail if the scan were stubbed — e.g.
  `MODELS_DISCOVERED` matching an independent recount — not merely on `VERDICT=PASS`.

## Task 6 — Wildcard gate with a correct command

`RawrRunWildcardAuthority` stays retracted unless wired to the real run path. If the
`rawr run` command is retested, use the documented order. Do **not** change
`rawr_run.cpp` parsing to accommodate `rawr run modelname "*" --tokens 5` — under the
parser at `:40-53` that form makes `--tokens 5` part of the prompt text, leaves
`maxTokens` at 512, and `modelname` is a placeholder that will not resolve. The parser
is correct; the command is wrong. If wildcard `*` expansion is a real product
requirement, specify its semantics separately first.

## Task 7 — Strict IDE chain (only after reboot passes)

`W8_HEADLESS_IDLE_LIFECYCLE_001` → `RAWRXD_GPU_CORRECTNESS_001` → `CHAT_E2E_IMMUTABLE_001`
→ `STRICT_WIN32IDE_CERTIFICATION_001`.

## Validation

1. `rawr dump --format receipt` on a machine with no model roots →
   `MODELS_DISCOVERED=0`, `VERDICT=FAIL`. **This is the key regression test** — it is
   impossible to pass with a stub.
2. Same command with known roots → counts match an independent `dir /s` recount.
3. `rawr dump --all` row count equals `MODELS_DISCOVERED`.
4. `RAWR_DUMP_RECEIPT_HAS_PASS` appears exactly once in receipt output.
5. Compare `GGUF_ARCH` / `GGUF_TENSOR_COUNT` against a known-good GGUF for a model on disk.
6. After reboot: `verify_rawr_after_reboot.ps1` → `PATH_RESOLVES_RAWR=1`, real
   `GENERATED_TOKEN_COUNT>0`.

## Risks

- **Ledger contamination (highest).** A `VERDICT=PASS` in a durable receipt is
  unrecoverable without invalidating everything referencing it. Retract first.
- **Parser reuse may not link.** `analyzer_distiller` may not be in the `rawr` target's
  CMake source list; if so, adding it is a one-time build change. Check before assuming.
- **The same stub pattern is repo-wide.** `CpuGpuComputeCompare.cpp:36-37` sets
  `cpuTps = 1000.0` / `gpuTps = 5000.0` with `// Example` comments. A broader audit is
  warranted before certifying any further authority — recommend scheduling it.
- Reboot is not undoable; the verifier must be correct before rebooting, not after.

## Out of scope

- Re-running or reverting the dump build fixes (closed).
- The IDE / W8 / GPU chain implementation.
- Re-litigating the installed-binary verdict (already correct).
