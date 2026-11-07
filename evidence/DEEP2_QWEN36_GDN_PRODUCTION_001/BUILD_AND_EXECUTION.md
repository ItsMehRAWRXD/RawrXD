# Qwen3.6 production-executor witness

Worktree: `F:\rawrxd`
Model: `F:\OllamaModels\Qwen3.6-35B-A3B-GGUF\Qwen3.6-35B-A3B-Q4_K_M.gguf`
Model SHA-256: `4AC6A06BCE551257267F49AD2226F8671A22519CCC1A4DDE9D5B433D1F2A410D`
Current executable: `F:\rawrxd\build_ide\bin\deep2_gpu_certify.exe`
Executable SHA-256: `49E8A39541683A6A66728C3DD4581EA884CA9B6855B9AEB79110A99D9C9A3CCE`

Build command:

```text
cmake --build F:\rawrxd\build_ide --target deep2_gpu_certify --parallel 4
```

Runtime command:

```text
DEEP2_GDN_GPU_CHECK=1 deep2_gpu_certify.exe --model Qwen3.6-35B-A3B-Q4_K_M.gguf --tokens "1 185" --dump gpu_certify_r2
```

Observed execution:

```text
arch=qwen35moe blocks=40 embd=2048 vocab=248320 experts=256 used=8
[gpu] gpu_calls=2602 cpu_calls=0 fallback=<none>
pos=0 vocab=248320 finite=248320 gpu_argmax=91664 cpu_argmax=110817 cos=0.9946897 max_abs=1.085 FAIL
pos=1 vocab=248320 finite=248320 gpu_argmax=9022 cpu_argmax=9022 cos=0.9993592 max_abs=0.5272 PASS
VERDICT=INTERNAL_DIAGNOSTIC_FAIL
CERT_STATUS=EXECUTION_PASS_WITH_INTERNAL_DIAGNOSTIC
CERTIFICATION_STATUS=BLOCKED_NO_INDEPENDENT_REFERENCE
EXIT=2
```

The run completed both tokens with zero CPU fallback calls and finite full
vocabulary logits. It did not certify full-model parity because the first
position failed the GPU-vs-CPU diagnostic and no independent reference logits
were supplied.

