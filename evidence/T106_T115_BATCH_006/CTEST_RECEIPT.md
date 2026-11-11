# CTest / Deep2 GPU batch receipt

## Run authority

The suite was run from the current Windows build tree after regenerating the
tracked Deep2 Qwen4Exp GDN SPIR-V artifact. The Win32 IDE executable was not
rebuilt by this test.

```ini
TEST_DIR=F:\rawrxd\build_repair_candidate
CONFIG=Release
SOURCE_HEAD_AT_TEST=b9fa16824277e17c3fb32e192d0105edd29e60b0
GDN_SHADER=F:\rawrxd\src\deep2\shaders\deep2_qwen4exp_gdn.spv
GDN_SHADER_SIZE=8692
```

## Command and result

```ini
COMMAND=ctest --test-dir F:\rawrxd\build_repair_candidate -C Release --output-on-failure
TESTS_TOTAL=28
TESTS_PASSED=27
TESTS_FAILED=0
TESTS_SKIPPED=1
EXIT_CODE=0
```

The skipped test is `deep2_h11_prefill_parity`; it is an environment-gated
parity test and did not run. The other 27 tests executed and passed.

## Relevant gates

```ini
T071_BACKEND_TEST_HARNESS=PARTIAL
T106_PREFILL_DECODE_BENCHMARK=NOT_VERIFIED
T107_GPU_BACKEND_CORRECTNESS=PASS_FOR_EXECUTED_CTESTS
T108_MODEL_LOAD_UNLOAD_STABILITY=NOT_VERIFIED
T115_OFFLINE_OPERATION=NOT_VERIFIED
```

The real `deep2_vulkan_gdn_dispatch` probe passed after the required tracked
SPIR-V artifact was restored. This is a GPU operator/parity result, not proof
of full IDE CPU/Vulkan/Ollama route attribution or heterogeneous multi-GPU
correctness.

## Controls

```ini
SOURCE_MUTATION_DURING_RUN=0
IDE_BINARY_MUTATION=0
PROMOTE=0
CERTIFIED=0
```
