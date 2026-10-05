# RAWRXD_ROOT_RECEIPTS_PROMOTION_001

Durable receipts recovered from the repository root during
`RAWRXD_REPOSITORY_HYGIENE_001`, where root-level `.txt` / `.log` output was
being removed from the index as scratch.

Each file below was classified by **content**, not by name. The criterion was
whether it carries a gate identity, a measurement, or a provenance hash that a
later session could not reconstruct from a re-run. Files that were merely
captured stdout were left to be dropped.

## Promoted

| promoted path | originating root path | gate / identity |
|---|---|---|
| `autoclose_RAWRXD_AUTOCLOSURE_001.txt` | `autoclose_receipt.txt` | `RAWRXD_AUTOCLOSURE_001` |
| `test_receipt_RAWRXD_AUTOCLOSURE_001.txt` | `test_receipt.txt` | `RAWRXD_AUTOCLOSURE_001` |
| `W8_HEADLESS_IDLE_LIFECYCLE_001.txt` | `w8_headless_lifecycle_receipt.txt` | `W8_HEADLESS_IDLE_LIFECYCLE_001` |
| `RAWRXD_MODEL_ROUTER_001.txt` | `rawrxd_model_router_receipt.txt` | `RAWRXD_MODEL_ROUTER_001` |
| `DEEP2_TOKEN_BEACON_FERRIS_001.txt` | `receipt_token_beacon_ferris_001.txt` | `DEEP2_TOKEN_BEACON_FERRIS_001` |
| `EMPIRICAL_TPS_DATASET.txt` | `empirical_tps_dataset.txt` | multi-gate TPS harvest |
| `qwen15b_Modelfile.txt` | `qwen15b_modelfile.txt` | Ollama Modelfile, `qwen2.5-coder:1.5b-base` |

## Why each was preserved rather than dropped

```ini
autoclose_RAWRXD_AUTOCLOSURE_001.txt
  MODEL_SHA256          = adbd048b1738782bc13819c08c3a14f7fbe9633b13e84d04de96b57e106c6e08
  MODEL_FILE_SIZE_BYTES = 699066720
  MODEL_LOADED=PASS  TOKENIZER_READY=PASS  FORWARD_PASS_OK=PASS
  -> binds a result to a specific model by content hash

test_receipt_RAWRXD_AUTOCLOSURE_001.txt
  same MODEL_SHA256, same NONCE field EMPTY
  MODEL_LOADED=PASS  TOKENIZER_READY=FAIL  FORWARD_PASS_OK=FAIL
  -> retained because it is the FAILING counterpart of the passing run above.
     Two receipts for one gate, one PASS and one FAIL, is a measurement pair;
     dropping the failure would leave a lone success that reads as stronger
     than the evidence supports.

W8_HEADLESS_IDLE_LIFECYCLE_001.txt
  DURATION_TARGET_SEC = 1800   DURATION_ACTUAL_SEC = 1800
  CERT_STAY_ALIVE=1  CERT_TIMER_EXPIRED=1
  MODEL_LOADED=0  DEEP2_USED=0  OLLAMA_USED=0
  -> an idle-lifecycle result, distinct from the inference gates

RAWRXD_MODEL_ROUTER_001.txt
  ROUTE=DEEP2_GGUF  DEEP2_USED=1  OLLAMA_USED=0
  MODEL_LOAD=FAIL  GENERATION_COMPLETED=0
  -> a FAILING routing receipt. Preserved for the same reason as above.

DEEP2_TOKEN_BEACON_FERRIS_001.txt
  STATUS=ACTIVE  (explicitly NOT PASS/FAIL)
  -> two-GPU placement experiment, Qwen2.5-Coder-32B, 19851336672 bytes.
     Its own STATUS field says the gate is unresolved, which is itself the
     durable fact.

EMPIRICAL_TPS_DATASET.txt
  -> provenance-preserving harvest across many gates, each row carrying
     model_bytes / generation_ms / decode_tps. Not reproducible by re-running
     one gate; it aggregates measurements from receipts that are now gone.

qwen15b_Modelfile.txt
  -> pinned by blob digest sha256-6a77366395772462...
```

## Explicitly NOT promoted

Three root `.txt` files passed a naive "is it structured?" test and were then
rejected on inspection. Recording why, because the naive test accepted them:

```ini
header_disk.txt   38.4 KiB   NOT A RECEIPT
header_disk2.txt  40.2 KiB   NOT A RECEIPT
tmp_audit_poll.txt 0.3 KiB   NOT A RECEIPT
```

`header_disk.txt` and `header_disk2.txt` are copies of a C++ header
(`vulkan_compute.h`) saved with a `.txt` extension — they begin `#pragma once`
and `#include <vulkan/vulkan.h>`. They matched "is it markdown/receipt"
heuristics only by accident. The real header is tracked at its own path; these
are disk scratch from a copy-paste.

`tmp_audit_poll.txt` is captured polling output (`GEN_DECODE_LIMIT=192
specActive=0` interleaved with tool-exit lines), with the word "audit" in a
tool name rather than a gate identity.

## Status

```ini
RAWRXD_ROOT_RECEIPTS_PROMOTION_001 = MEASURED_CONTENT_CLASSIFIED
ROOT_RECEIPTS_PROMOTED           = 7
ROOT_RECEIPTS_REJECTED_AFTER_READ = 3
PASS_AND_FAIL_PAIRS_RETAINED      = 2  (AUTOCLOSURE, MODEL_ROUTER)
ORIGINALS_DELETED_FROM_DISK      = 0
```

The root originals still exist on disk. This promotion is what allows them to
leave version control without losing the evidence.