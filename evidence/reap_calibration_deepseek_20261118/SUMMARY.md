# REAP calibration and MoE evidence

Model: `models/deepseek-coder-v2_16b.gguf`

The calibration CLI ran against the real DeepSeek MoE GGUF, not the dense Qwen fixture.

```ini
MODEL_ARCH=deepseek2
LAYERS=27
EXPERTS_PER_LAYER=64
ACTIVE_EXPERTS=6
CALIBRATION_EXIT=0
RANKING_FILES=27
RANKING_WIDTH=64
MANIFEST=calibration_manifest.json
MARS_PLACEMENTS=27
MARS_ACCOUNTING_FREED=187.95MB
```

The run emitted real routing/placement activity and completed calibration. It also reported `DEEP2_GPU_FORWARD_FALLBACKS=1` and did not produce an independent GPU-vs-CPU expert-output comparison. Therefore:

```ini
REAP_CALIBRATION_RUNTIME=PASS_FOR_FIXTURE
GPU_MOE_PARITY=NOT_ESTABLISHED
DUAL_GPU_MARS_MIGRATION=NOT_ESTABLISHED
```
