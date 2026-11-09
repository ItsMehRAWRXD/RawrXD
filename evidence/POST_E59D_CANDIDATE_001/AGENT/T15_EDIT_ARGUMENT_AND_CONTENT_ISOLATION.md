# T15_EDIT_ARGUMENT_AND_CONTENT_ISOLATION

ASOF_UTC=2026-11-08T22:40:00Z
GATE=T15_EDIT_ARGUMENT_AND_CONTENT_ISOLATION
SCOPE=rawr.exe agent (≠ Win32IDE CERT SHA promote)
WIN32IDE_CERT_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
CLI_PREFERRED=F:\rawrxd\build_ide\bin-msvc\rawr.exe
CLI_PREFERRED_PRESENT=0
CLI_UNDER_TEST=F:\rawrxd\build_repair_candidate\bin-msvc\rawr.exe
CLI_SHA=2CB32D51F4C4CFE3138C7869365A4DBC22CE1DA5F6F16B1920BFE8FFB1C182AF
MODEL=qwen3:8b
BACKEND=ollama
REBUILD=HELD
PROMOTE=0
CERTIFIED=0

## Prior sealed residual (7bb4df317c)

Authority: `AGENT\T15_DISK_VERIFY.md` · `AGENT\EDIT_POST.txt` · `AGENT\ESP_EDIT.txt` · `AGENT\harness_agent_tools_cancel.ps1`

```
PROMPT_REQUESTED=before=0→1 AND append comment T15_EDITED_<marker>
HARNESS_PASS_OR=marker OR before=1   # WEAK — false PASS path
ESP=editFiles TOOL_RESULT status=PASS target=t15_edit_T15_7bb4df317c.cpp
DISK_AFTER=// EDIT_ME T15_7bb4df317c\nint before = 1;
MARKER_PRESENT=False
SHA256=0072479256D2F56220995BD21727CC30220E445AF1792145947084D96EE9CCB1
PRIOR_ESP_ARGS=NOT_CAPTURED (ESP logs target only)
```

## Live isolation (marker T15ISO_211f6c25)

Artifacts: `AGENT\T15_ISOLATION\`

### A) Direct `rawr tools run editFiles` (product path)

Captured args (DIRECT_STDOUT.json / tool_receipts):

```json
{"old":"int before = 0;","new":"int before = 1;\n// T15_EDITED_T15ISO_211f6c25","path":"...\\t15_direct_T15ISO_211f6c25.cpp"}
```

```
DIRECT_EXIT=0
DISK_AFTER:
  // EDIT_ME T15ISO_211f6c25
  int before = 1;
  // T15_EDITED_T15ISO_211f6c25
MARKER_REQUESTED=YES
MARKER_ON_DISK=YES
PRODUCT_APPLIES_ARGS=PASS
```

### B) Model one-shot (`rawr run ... --prompt` + --approve-mutations)

Captured args (`AGENT_SESSION_AFTER.json` tool_calls[0]):

```json
{"tool":"editFiles","ok":true,"args":{"old":"before = 0","new":"before = 1 // T15_EDITED_T15ISO_211f6c25","path":"...\\t15_iso_T15ISO_211f6c25.cpp"}}
```

```
DISK_AFTER:
  // EDIT_ME T15ISO_211f6c25
  int before = 1 // T15_EDITED_T15ISO_211f6c25;
MARKER_REQUESTED_IN_ARGS=YES (mangled onto same statement)
MARKER_SUBSTRING_ON_DISK=YES
PRODUCT_APPLIED_ARGS_FAITHFULLY=YES
MODEL_INSTRUCTION_QUALITY=PARTIAL (syntax-mangled new=)
```

## Root-cause classification

```
ROOT_CAUSE=MODEL_EDIT_ARGS_PARTIAL_OR_MANGLED
PRODUCT_DEFECT=NOT_PROVEN
PRODUCT_PERSISTENCE_DEFECT=NOT_PROVEN
HARNESS_WEAK_OR_ACCEPTANCE=PROVEN (v1 harness FILE_EDIT PASS on before=1 alone)
PRIOR_7bb4df_MARKER_ABSENT => model almost certainly omitted marker from editFiles new=
  (product proven to write marker when present in args)
REPAIR_AUTH_NEED=NONE_FOR_PRODUCT (no IDE/rawr rebuild authorized; REBUILD=HELD)
NEXT_IF_HARDENING=optional harness tighten (require marker substring; do not OR before=1)
```

## Disposition

```
T15_EDIT_ARGUMENT_AND_CONTENT_ISOLATION=CLOSED
T15_EDIT_CONTENT=FAIL_PRIOR_DISK / ISOLATED
T15_EDIT_CONTENT_RESIDUAL=CLOSED_AS_MODEL_ARGS_NOT_PRODUCT
WIN32IDE_PROMOTE=0
```
