# Native Deep2 text-tool protocol receipt

Date: 2026-10-28
Source root: `F:\rawrxd`
Branch: `fix/deep2-multimodel-safety-20261025`
Source commit: `825f7479472e86575917e50392c0d8178cc26f45`

## Change

The native Deep2 CLI path now uses the shared strict parser in
`src/agentic/NativeToolProtocol.h`. It accepts only complete `TOOL read`,
`TOOL write`, `TOOL build`, and `TOOL test` commands, removes end-of-turn
markers only at the response boundary, rejects prose/trailing chatter/arbitrary
shell, and feeds real tool results back into the native prompt. A native
`TOOL finish` is fail-closed until host verification exists.

## Build and unit evidence

```ini
BUILD_COMMAND=cmake --build F:\rawrxd\build_ide --target native_tool_protocol_smoke RawrXD-CLI-V2 --parallel 8
BUILD_ENV=Visual Studio 2022 Developer Command Prompt 17.14.39 amd64
BUILD_EXIT=0
CLI_PATH=F:\rawrxd\build_ide\bin-msvc\rawr.exe
CLI_SHA256=D5DA848C0BA1D90E4B8DCDA101332161F750581249DCA18A4F1F47E65BFE5296
CTEST_COMMAND=ctest --test-dir F:\rawrxd\build_ide -R native_tool_protocol_smoke|workspace_path_policy_smoke|cursor_parity_registry_smoke --output-on-failure
CTEST_RESULT=3/3 passed, 0 failed
NATIVE_TOOL_PROTOCOL_SMOKE=PASS, FAIL_COUNT=0
PROMOTE=0
```

## Real Ollama regression

```ini
MODEL=qwen3:8b
BACKEND=ollama
WORKSPACE_ROOT=F:\rawrxd
MODE=autonomous (requested --mode agent)
MOTD_ACK=1
TOOL_READ=PASS
TOOL_CALLS=1
TASK_RESULT=PASS
PROCESS_EXIT=0
SOURCE_MUTATION=NOT_OBSERVED
STDOUT_SHA256=A89F5E669ADC2CEF16A96450B8720FA242F02C2C758D9C0676A62914D38C5733
STDERR_SHA256=91FB1D100CE1A78E3D7A42280A5EBBE17CE41F3945848907633F0B0DE99CCF60
ESP_SHA256=436E5C83C8822E2E02488592801A7B8ABF944E06B33658A71B6CE33D8EF82713
```

Evidence:

- `F:\rawrxd\tmp_build\native_tool_protocol_qwen_regression.stdout.txt`
- `F:\rawrxd\tmp_build\native_tool_protocol_qwen_regression.stderr.txt`
- `F:\rawrxd\tmp_build\native_tool_protocol_qwen_regression.jsonl`

## Native Deep2 probe

The local GGUF probe was bounded at 45 seconds and did not reach a native tool
call. It is preserved as a failure/incomplete witness, not a certification:

```ini
MODEL=G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
BACKEND=deep2
MODEL_LOAD=PASS_OBSERVED
GPU_BACKEND=OBSERVED
GPU_DEVICE=AMD Radeon AI PRO R9700
GPU_CODE31=PROBLEM_CODE=31 RESET_ATTEMPTED=1 RESET_OK=0 ACCESS_DENIED=1 HEALTHY=0
GENERATED_TOKENS=1
TOOL_CALLS=0
CANCELLATION=COOPERATIVE
PROCESS_EXIT=130
NATIVE_DEEP2_AGENT_E2E=NOT_VERIFIED
```

Evidence:

- `F:\rawrxd\tmp_build\native_tool_protocol_deep2_tiny.stdout.txt` (SHA-256 `B630DAABD7A693AFC0A408D44BB1AA8D53278F0F32F3DE07621E2396690B5F16`)
- `F:\rawrxd\tmp_build\native_tool_protocol_deep2_tiny.stderr.txt` (SHA-256 `F968EFF86784D0D7129AD2144BE4CCBC6530A80571A4F853C1C981EE766BEC8E`)
- `F:\rawrxd\tmp_build\native_tool_protocol_deep2_tiny.jsonl` (SHA-256 `D07BC1F8257281F64D503E48DF5802DD2FC2CB03519AD3397B156A1B4551539B`)

This does not alter the frozen product authority. Product certification remains
bound to the separately recorded `748B210A...` executable, and `PROMOTE=0`.
