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

## Current development binary witness

A subsequent development link produced a different non-authoritative binary
hash without changing the source commit. The earlier `814AE04C...` witness is
preserved above; this is the current executable baseline:

```ini
SOURCE_COMMIT=3b0392f96f1f912594ed278e61199c2b52080476
CLI=F:\rawrxd\build_ide\bin-msvc\rawr.exe
CLI_SHA256=2787C418C9AAF613EF7E39DD6D02EFC22C985C6C235A964450ADAE4484468233
COMMAND=rawr run qwen3:8b --backend ollama --mode ask --workspace F:\rawrxd --fresh-session --max-tokens 16 --context 4096 --esp=tps --task "Reply exactly RAWRXD_CURRENT_LIMIT_PASS"
EXIT_CODE=0
REQUESTED_MAX_TOKENS=16
REQUESTED_CONTEXT=4096
APPLIED_MAX_TOKENS=16
APPLIED_CONTEXT=4096
OUTPUT_MARKER=RAWRXD_CURRENT_LIMIT_PASS
ESP_FINISHED=PASS
STDOUT=current.stdout.txt
STDOUT_SHA256=0B5F968402E17D6A77923A5D82644A07C856FAE239475C18342AF472522EFBA9
STDERR=current.stderr.txt
STDERR_SHA256=AB73D0B729AA97546E2088EE6A880D6490CF64589AE46D5DBF9BC43CCBCBC352
ESP=current.esp.jsonl
```

## Current CLI agent regression

```ini
CLI_SHA256=2787C418C9AAF613EF7E39DD6D02EFC22C985C6C235A964450ADAE4484468233
COMMAND=rawr run qwen3:8b --backend ollama --mode agent --workspace F:\rawrxd --fresh-session --max-tokens 64 --context 4096 --esp=tps --task "read-only calc.cpp verification"
EXIT_CODE=0
MODEL_INFERENCE=REAL
MOTD_ACK=1
REQUESTED_MAX_TOKENS=64
APPLIED_MAX_TOKENS=64
REQUESTED_CONTEXT=4096
APPLIED_CONTEXT=4096
TOOL_START=readFile
TOOL_TARGET=tmp_build/cli_smoke_20261028/fixture/calc.cpp
TOOL_RESULT=PASS
SOURCE_CONTENT=int main(){return 0;}
FILE_SHA256_BEFORE=85D5D0C9E29F65E3FE6FBF25B7939530FB5B397EC258DF70E9CF0068A673A45
FILE_SHA256_AFTER=85D5D0C9E29F65E3FE6FBF25B7939530FB5B397EC258DF70E9CF0068A673A45
FILE_MODIFIED=0
TASK_RESULT=RAWRXD_AGENT_READ_PASS
ESP_FINISHED=PASS
STDOUT=qwen_readonly.stdout.txt
STDOUT_SHA256=86E44522C202C1B3B10CFD9B6341055CBC166444ACE65A9E6EFD544D04E4BF90
STDERR=qwen_readonly.stderr.txt
STDERR_SHA256=A463141B24D6501C47583B342D3B642E1108A4B088C9105B429F43254D09F303
ESP=qwen_readonly.esp.jsonl
```

```ini
PROMOTE=0
```
