# T026-T055 CLI and cancellation certification receipt

This receipt supersedes no prior candidate. It records a new CLI-only
candidate after the Windows Git revision-reporting fix. The Win32 IDE binary
was not rebuilt or replaced by this batch.

## Candidate authority

```ini
BINARY=F:\rawrxd\build_repair_candidate\bin-msvc\rawr.exe
SIZE=5020160
SHA256=706D52A24E4A688DFA0A74C20404CD49B8990AEB21815F830296D6C52FCB5847
SOURCE_HEAD=50a8e65db9a001eda1f1306cf8dff999996ef524
REMOTE_BRANCH=fix/deep2-multimodel-safety-20261025
```

## Executed gates

```ini
T026_TARGET_AND_PROVENANCE=PASS
T027_MODE_PARSING=PASS
T028_MODE_AUTHORIZATION=PASS
T029_JSON_AND_ARGUMENT_PARSING=PASS
T030_EDITFILES_EXACT_REPLACEMENT=PASS
T033_DIRECT_TOOL_RECEIPTS=PASS
T034_WORKSPACE_BOUNDARY=PASS
T035_DIRECT_TOOL_DISPATCH=PASS
T036_OLLAMA_BASELINE=PASS
T046_REQUEST_A_STOP_B=PASS_BEHAVIORALLY
T047_CANCELLATION_STRESS=PASS
T048_LATE_CALLBACK_FENCE=PASS_IN_CLI_PATH
T053_TIMEOUT_AND_EXIT=PASS
T054_CHILD_PROCESS_CLEANUP=PASS
T116_MANIFEST_SOURCE_REVISION=PASS
```

## Physical evidence

### Manifest consistency

```ini
CTEST=PASS
TEST=gate2_manifest_consistency
RESULT=100_PERCENT_OF_SELECTED_TESTS_PASSED
```

The test cross-checked the authoritative registry and `rawr capabilities`
manifest, including the source revision, primitive set, binding status,
quantization evidence, and cited parity artifacts.

### Normal inference

```ini
COMMAND=rawr run qwen3:8b autonomous --backend ollama --workspace F:\rawrxd --max-tokens 128 --context 8192 --fresh-session
EXIT=0
MARKER=AGENT_SIMPLE_OK
```

### Cancellation stress

```ini
COMMAND=rawr run qwen3:8b --backend ollama --workspace F:\rawrxd --max-tokens 4096 --context 65536 --cancel-after-ms 250
CYCLES_COMPLETED=25
EXIT_CODE_EACH_CYCLE=130
CANCEL_RECEIPT_EACH_CYCLE=1
PASS_COUNT=25
FORCED_KILLS=0
ORPHAN_RAWR=0
```

The 25 cycles were executed against this exact SHA in one completed shell
campaign. Each process returned the cancellation exit code and emitted the
user-interrupt cancellation receipt.

### Direct tool and policy checks

```ini
READ_MOTD_EXIT=0
EDITFILES_MODE=autonomous
EDITFILES_EXIT=0
EDITFILES_BEFORE_SHA=DC1447F6F6849B9D99913033E55A56302776039D97C28CC1D4EF8AF6DAAEA7F8
EDITFILES_AFTER_SHA=1BD9AFEABEEA8CF0C8875754BDC136F3596404D3850B1299EA93E8019F8F3A9F
EDITFILES_DISK_MATCH=1
TRAVERSAL_EXIT=1
TRAVERSAL_DENIED=1
```

The direct `editFiles` receipt is present in
`.rawrxd/ledger/tool_receipts.jsonl` with the same `706D52A2...` binary hash.

## Controls and limits

```ini
IDE_BINARY_MUTATION=0
IDE_REBUILD=0
PROMOTE=0
CERTIFIED=0
```

This closes the current CLI/cancellation evidence batch. It does not certify
the Win32 IDE, Deep2 Vulkan GDN dispatch, or independent T25 review. The full
CTest run still has a separate Vulkan GDN failure and one skipped prefill
parity test; those remain open under their own gates.
