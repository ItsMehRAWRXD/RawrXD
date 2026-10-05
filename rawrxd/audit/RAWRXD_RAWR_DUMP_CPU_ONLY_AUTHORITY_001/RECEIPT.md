# RAWRXD_RAWR_DUMP_CPU_ONLY_AUTHORITY_001

Promotion of the durable measurements from two unnamed scratch receipts at the
repository root (`_rawr_dump_receipt.txt`, `_rawr_dump_cpu_only_receipt.txt`)
into a named audit location, so the tracked copies can be released from the
index without destroying the evidence.

This is an evidence **promotion**, not a certification. Nothing here promotes a
ledger gate. See "Status" for why.

## Provenance gap — read this before citing any number below

The two source receipts recorded **no provenance identity whatsoever**:

```ini
BINARY_IDENTITY_RECORDED = 0
SHA256_RECORDED          = 0
COMMIT_RECORDED          = 0
TIMESTAMP_RECORDED       = 0
SOURCE_RECEIPT_BYTES     = 736 / 401
```

`git log` places their last modification in `a207ebec4`, but that commit's
subject concerns DeepSeek GGUF location and zero-logit localisation — it is not
a dump-authority certification and does not claim to have produced them.

Consequence: these measurements describe *some* build of `rawr.exe`, and
nothing in the evidence identifies which one. Per the project evidence law
(`CLAIM_RUNTIME_WORKS_REQUIRES_RUNTIME_EVIDENCE=1`, and the receipt-seal rule
`EXPECTED_BINARY_SHA256 == ACTUAL_BINARY_SHA256`), an unbound measurement
cannot certify a binary. Treat every field below as **evidence of a run whose
executable identity is unknown**, not as a reproducible result.

## RAWRXD_RAWR_DUMP_AUTHORITY_001

Verbatim from `_rawr_dump_receipt.txt`:

```text
GATE=RAWRXD_RAWR_DUMP_AUTHORITY_001
COMMAND=rawr dump
GENERATED_FROM_SCRATCH=1
CONFIG_USED=filesystem_scan
ROOTS_SCANNED=2
ROOTS_SKIPPED_MISSING=0
ALIASES_SCANNED=0
OLLAMA_MANIFESTS_SCANNED=168
GGUF_FILES_SCANNED=75
MODELS_DISCOVERED=222
MODELS_CLASSIFIED=222
MODELS_WITH_PATH=109
MODELS_WITH_UNKNOWN_PATH=113
SELECTION_QUERY=tiny
SELECTION_STATUS=MATCH
SELECTION_MATCHES=1
DEEP2_COMPATIBLE_COUNT=109
UNLOADABLE_COUNT=113
DUPLICATES_REMOVED=21
OUTPUT_FORMAT=json
OUTPUT_PATH=
DEEP2_GENERATION_CALLED=0
GENERATE_STREAM_CALLED=0
GPU_INIT_CALLED=0
VULKAN_INIT_CALLED=0
```

## RAWRXD_RAWR_DUMP_CPU_ONLY_AUTHORITY_001

Verbatim from `_rawr_dump_cpu_only_receipt.txt`:

```text
GATE=RAWRXD_RAWR_DUMP_CPU_ONLY_AUTHORITY_001
RAWR_DUMP_ENTERED=1
FILESYSTEM_SCAN=1
OLLAMA_MANIFEST_RESOLUTION=168
GGUF_HEADER_PARSE=75
GGUF_KV_PARSE=75
TENSOR_COUNT_FROM_METADATA=75
DEEP2_GENERATION_CALLED=0
GENERATE_STREAM_CALLED=0
GPU_INIT_CALLED=0
VULKAN_INIT_CALLED=0
VRAM_ALLOCATED=0
LOGITS_REQUIRED=0
GENERATED_TOKEN_COUNT=0
GPU_REQUIRED=0
NO_GPU_ENV_SUPPORTED=1
EMPTY_ROOT_RETURNS_FAIL=0
REAL_ROOT_RETURNS_PASS=1
STUB_FALLBACKS=0
MODELS_DISCOVERED=222
MODELS_WITH_PATH=109
VERDICT=PASS
```

### CPU-only invariants these receipts assert

The distinguishing content of the CPU-only gate is the zero-call set. These are
the load-bearing claims — a `rawr dump` that touched GPU or generation would
not be a CPU-only path:

```ini
DEEP2_GENERATION_CALLED = 0
GENERATE_STREAM_CALLED   = 0
GPU_INIT_CALLED          = 0
VULKAN_INIT_CALLED       = 0
VRAM_ALLOCATED           = 0
GPU_REQUIRED             = 0
NO_GPU_ENV_SUPPORTED     = 1
```

Two fields weaken the "CPU-only" framing and are carried forward rather than
dropped:

- `EMPTY_ROOT_RETURNS_FAIL=0` — an empty root did **not** return FAIL. The
  ledger for the dump authority requires that a scan finding nothing report
  `MODELS_DISCOVERED=0` and `VERDICT=FAIL`, precisely because the previous stub
  reported a hardcoded PASS. A recorded `0` here is contrary to that
  requirement and is unexplained.
- `STUB_FALLBACKS=0` — asserted, with no supporting field that could falsify
  it. Nothing in either receipt measures stub usage; the value is a literal.

## Relationship to RAWRXD_DUMP_AUTHORITY_SELECTION_001

Five fields appear in that document's "Measured effect" table with identical
AFTER values (`MODELS_DISCOVERED=222`, `MODELS_WITH_PATH=109`,
`MODELS_WITH_UNKNOWN_PATH=113`, `UNLOADABLE_COUNT=113`, `DUPLICATES_REMOVED=21`).
The catalog-scan numbers are therefore already captured in a named audit
document.

What is **not** captured anywhere named is the CPU-only invariant set above, the
`RAWRXD_RAWR_DUMP_AUTHORITY_001` gate header, and the scan geometry
(`ROOTS_SCANNED=2`, `OLLAMA_MANIFESTS_SCANNED=168`, `GGUF_FILES_SCANNED=75`,
`SELECTION_*`). Promoting them is the purpose of this file.

## Status

```ini
RAWRXD_RAWR_DUMP_CPU_ONLY_AUTHORITY_001 = MEASURED_UNBOUND_BINARY
VERDICT_PRESERVED_FROM_SOURCE          = PASS
CHAIN_CERTIFIED                        = NO
```

The source receipt's `VERDICT=PASS` is preserved verbatim above and is **not**
endorsed. It is not endorsed for two independent reasons:

1. **No binary identity.** The receipt cannot be bound to an executable, so
   the seal rule that makes any other certification in this repository valid
   does not apply to it.
2. **The chain it would certify through is itself retracted.**
   `RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001=RETRACTED_FALSE_PASS` — the
   mutable receipt API is what these files were written through.

`RAWRXD_DUMP_AUTHORITY_SELECTION_001` states the same conclusion explicitly and
this promotion does not override it:

> It is not a ledger gate receipt and does not promote
> `RAWRXD_RAWR_DUMP_CPU_ONLY_AUTHORITY_001` to certified.

Per the standing rule honoured there:

```ini
LEDGER_SAYS_FAILS -> no later conversational PASS overrides it
```

## Superseded by two other tracked copies — read this before citing

Two receipts with the same gate names exist at `rawrxd/_rawr_dump_receipt.txt`
and `rawrxd/_rawr_dump_cpu_only_receipt.txt`. They are **not** duplicates of the
root copies: they differ.

```text
                            root (promoted here)   rawrxd/ (tracked)
_rawr_dump_receipt.txt      MODELS_DISCOVERED=222  not present (30 vs 33 lines)
_rawr_dump_cpu_only_receipt MODELS_DISCOVERED=222  MODELS_DISCOVERED=206
                            MODELS_WITH_PATH=109   MODELS_WITH_PATH=78
```

The `rawrxd/` copies carry the **pre-fix** figures (206 / 78), which match the
BEFORE column of `RAWRXD_DUMP_AUTHORITY_SELECTION_001`'s "Measured effect"
table. The root copies carry the AFTER figures (222 / 109).

Consequences:

- The AFTER measurements promoted here are the current ones and are the
  authoritative values.
- The `rawrxd/` copies are retained as the **before** measurement, which is what
  makes that table falsifiable. They are kept tracked for that reason and are
  named here rather than silently duplicated.
- Had the rawrxd/ copies been the ones promoted, this receipt would have
  recorded stale numbers while claiming to describe the same gate.

## What re-running would settle

`EMPTY_ROOT_RETURNS_FAIL=0` and the unfalsifiable `STUB_FALLBACKS=0` are the two
defects this promotion surfaces. Both are cheap to settle: point `rawr dump` at
an empty root and assert `VERDICT=FAIL`, and add a field that actually counts
stub returns. Neither is attempted here — this tranche is repository hygiene,
and a gate is not closed by rewriting its receipt.