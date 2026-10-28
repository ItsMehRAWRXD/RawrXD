# Rawr CLI Runtime Configuration Receipt

```ini
SOURCE_ROOT=F:\rawrxd
BRANCH=fix/deep2-multimodel-safety-20261025
SOURCE_COMMIT_BEFORE=15717abf3c5db189e9096863a30d6b09b584b056
CLI=F:\rawrxd\build_ide\bin-msvc\rawr.exe
CLI_SHA256=814AE04C6761800722EBACC2EBFE0910D860F3190BC7EB7B5F0F1BED02BD65B0
BUILD=MSVC 17.14.39 amd64 / CMake Ninja
```

## Positive live Ollama request

```ini
COMMAND=rawr run qwen3:8b --backend ollama --mode ask --workspace F:\rawrxd --fresh-session --max-tokens 16 --context 4096 --esp=tps --task "Reply exactly RAWRXD_POSTBUILD_LIMIT_PASS"
EXIT_CODE=0
MODEL=qwen3:8b
BACKEND=ollama
REQUESTED_MAX_TOKENS=16
REQUESTED_CONTEXT=4096
APPLIED_MAX_TOKENS=16
APPLIED_CONTEXT=4096
OUTPUT_MARKER=RAWRXD_POSTBUILD_LIMIT_PASS
ESP_FINISHED=PASS
STDOUT=postbuild.stdout.txt
STDOUT_SHA256=56422BF4437F9A5029A79D45C5A10E53B2AA4BB719668840C27AD8F4EE14ED6C
STDERR=postbuild.stderr.txt
STDERR_SHA256=D0F5F0944FAD84A3AB0925E4A311285D57445A015E21CDB0A6492A3A09C1C472
ESP=postbuild.esp.jsonl
```

## Negative validation

```ini
COMMAND=rawr run qwen3:8b --backend ollama --workspace F:\rawrxd --max-tokens 0 --task "invalid option probe"
EXPECTED=reject before backend initialization
OBSERVED=RUN_CONFIG_ERROR=invalid --max-tokens value (expected 1..65536)
EXIT_CODE=2
```

## Focused tests

```ini
CTEST_COMMAND=ctest --test-dir F:\rawrxd\build_ide -R native_tool_protocol_smoke|workspace_path_policy_smoke|cursor_parity_registry_smoke --output-on-failure
CTEST_EXIT=0
CTEST_PASS=3
CTEST_FAIL=0
```

This receipt covers CLI request-limit propagation only. Native Deep2 context
admission remains model/configuration controlled; Ollama context propagation is
the path exercised above. Product certification remains governed by the frozen
`748B210A...` authority and is not changed by this development CLI build.

```ini
PROMOTE=0
```
