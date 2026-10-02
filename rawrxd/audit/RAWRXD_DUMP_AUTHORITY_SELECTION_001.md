# RAWRXD_DUMP_AUTHORITY_SELECTION_001

Fixes to `rawr dump`, measured by execution against freshly linked binaries.

```ini
BEFORE_BINARY_SHA256 = E174761742EFD2EB9AC91205151AE591FB5EAFA2F1051BECE2483A594D609DE6
AFTER_BINARY_SHA256  = 7D0081DDDEF1582EAA2FC74013E75E74B0A5C5AD3F110A0A4901FD976C12EC26
BUILD                = cmake -S rawrxd -B build_dump_census -G Ninja -DRAWRXD_BUILD_CLI=ON
WORKTREE_CHANGED_PATHS_AT_MEASUREMENT = 301
```

`rawr.exe` had never been built in this workspace before this work. Both
options guarding it default OFF (`RAWRXD_BUILD_CLI`, `BUILD_RAWRXD_RUN_MODELNAME_001`,
CMakeLists.txt:498 and :10540), so the CLI is unreachable from a default
configure even though the target is defined at CMakeLists.txt:10576.

---

## Defect 1 — the verdict could not disagree with the result

`ModelCatalogAuthority`'s scan verdict was copied into the dump state and
inherited by every query, so a query matching nothing still reported `PASS`
and exited 0. The code comment said so explicitly:

```cpp
// Apply filters. A filter that eliminates everything yields an
// empty table, not a failure — the receipt still reports what
// was scanned.
```

Measured before the fix:

```text
COMMAND = rawr dump --format json tinyllama
JSON    = "model_count": 206, "models": [ ]
VERDICT = PASS          EXIT = 0
```

Fixed: selection is now evaluated and drives the verdict and the exit code.

```text
QUERY=gemma3:4b          EXIT=0  MATCHES=1  STATUS=MATCH           VERDICT=PASS
QUERY=gemma3:latest      EXIT=0  MATCHES=1  STATUS=MATCH           VERDICT=PASS
QUERY=llama3.2:3b        EXIT=0  MATCHES=1  STATUS=MATCH           VERDICT=PASS
QUERY=deepseek-r1:70b    EXIT=0  MATCHES=1  STATUS=MATCH           VERDICT=PASS
QUERY=qwen3:8b           EXIT=0  MATCHES=1  STATUS=MATCH           VERDICT=PASS
QUERY=kimi-k2.6:cloud    EXIT=1  MATCHES=1  STATUS=UNRESOLVED_PATH VERDICT=FAIL_UNRESOLVED_PATH
QUERY=gemma3             EXIT=1  MATCHES=6  STATUS=AMBIGUOUS       VERDICT=FAIL_AMBIGUOUS
QUERY=no_such_model_xyz  EXIT=1  MATCHES=0  STATUS=NO_MATCH        VERDICT=FAIL_NO_MATCH
```

Four distinct verdicts are reachable from input alone, which is the falsification
evidence that the verdict is computed rather than asserted.

## Defect 2 — Ollama tags were unreadable

`ModelCatalogAuthority.cpp:251` read the manifest tag and never used it, so
every model was stored without its tag and `findByName` collapsed
`gemma3:latest` and `gemma3:4b` into one record named `gemma3`. Names that
`ollama list` prints were unmatchable:

```text
QUERY=gemma3:4b          MATCHES=0   (before)
QUERY=kimi-k2.6:cloud     MATCHES=0   (before)
QUERY=llama3.2:3b         MATCHES=0   (before)
```

## Defect 3 — blob paths never resolved for Ollama models

An Ollama manifest is OCI JSON and writes digests with a **colon**
(`"digest":"sha256:<hex>"`), while the blob file on disk is named with a
**hyphen** (`sha256-<hex>`). The resolver searched for `"sha256-"`, which does
not occur in a real manifest, so all 128 unresolved models had empty paths.
The weights layer is identified by `mediaType ==
application/vnd.ollama.image.model`; the first digest in the document is the
small config blob, and a cloud-only manifest has no model layer at all and must
stay unresolved.

## Defect 4 — path dedup deleted the tags

`dedupeModelRecords` kept only the first record per path. Since the blob file is
also scanned as a GGUF, the file record won and every tag pointing at that blob
was deleted, so `llama3.2:3b` and `llama3.2:latest` both vanished. Two different
tags sharing one blob is the normal alias case, not a duplicate. Dedup is now
by name, with file-vs-tag collisions resolved in favour of the tag.

## Defect 5 — quantization was never read

`GgufMetadataProbe` read quantization only from a **string** key ending
`.quantization_type`. Real files store it in `general.file_type` as a **UINT32**
ggml enum, so `quantization` was empty for every model and the dump column
showed `?` across the whole catalog. Now read, with an enum table; an unlisted
value is reported as `FTYPE_<n>` rather than guessed.

## Defect 6 — large-vocabulary headers desynchronised the metadata walk

The probe read a fixed 8 MiB window. A 256K-token vocabulary puts the tokenizer
block past that, so `gemma3` reported `parsed: false` with `arch: gemma3` and
`quantization: ""` — a half-populated record indistinguishable from "this model
has no quantization". The window now escalates (8/32/128/512 MiB) until the KV
walk completes.

---

## Measured effect

```text
                        BEFORE   AFTER
MODELS_DISCOVERED         206     222
MODELS_WITH_PATH           78     109
MODELS_WITH_UNKNOWN_PATH  128     113
UNLOADABLE_COUNT          128     113
DUPLICATES_REMOVED          3      21
records with quantization   0      83   (Q4_K_M=47, Q2_K=10, Q4_0=9, Q8_0=5, ...)
```

`gemma3:4b` after the fix, cross-checked against an independent Python GGUF
reader: `parsed: true`, `arch: gemma3`, `tensor_count: 883`,
`quantization: Q4_K_M`, `general.file_type = 15`. The two readers agree.

## Remaining, stated rather than hidden

```text
MODELS_WITH_UNKNOWN_PATH = 113
  of which cloud-only manifests with no local weights = 26
  remainder = manifests whose blob is absent from the scanned store
              (largely hf.co registry entries under bartowski/, huihui-ai/)
```

Not closed. Per-model verification is required to distinguish "pruned blob"
from "store not scanned".

The table renderer also fuses the classification and quantization columns when
the class string is long (`medium/reasoningQ4_K_M`). Cosmetic, not fixed.

## Standing rule honoured

```ini
LEDGER_SAYS_FAILS -> no later conversational PASS overrides it
```

`RAWRXD_DUMP_AUTHORITY_SELECTION_001` records an implementation and a measured
run against one binary identity. It is not a ledger gate receipt and does not
promote `RAWRXD_RAWR_DUMP_CPU_ONLY_AUTHORITY_001` to certified.