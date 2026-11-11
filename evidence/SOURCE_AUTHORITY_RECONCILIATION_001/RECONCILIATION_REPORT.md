# SOURCE_AUTHORITY_RECONCILIATION_001

AUTHORITY_COMMIT=a5ae60efecac790598e2e46d9e499eb8ac7287af
LOCAL_HEAD=a5ae60efecac790598e2e46d9e499eb8ac7287af
LOCAL_EQUALS_AUTHORITY=True
SOURCE_MATERIAL_PATHS=37
PROMOTE=0

## Rule
- Tip `a5ae60ef` remains authority for seals.
- Dirty working tree ≠ tip; do not attribute product PASS to dirty binaries.
- INTENDED_WIP must be committed or branched before product seal; else revert to tip for candidate builds.

## Bucket counts
- REVIEW_BUILD_SURFACE: 1
- LIKELY_INTENDED_WIP: 12
- DRIFT_OR_UNKNOWN: 20
- TOOL_NOT_PRODUCT: 4

## Paths
- `CMakeLists.txt` | M | REVIEW_BUILD_SURFACE |  1 file changed, 76 insertions(+)
- `src/deep2/Deep2Engine.cpp` | M | LIKELY_INTENDED_WIP |  1 file changed, 2 insertions(+)
- `src/deep2/K2NativeMoEFfn_ExpertGpuDevice.cpp` | M | LIKELY_INTENDED_WIP |  1 file changed, 8 insertions(+)
- `src/deep2/K2NativeMoEFfn_Place.cpp` | M | LIKELY_INTENDED_WIP |  1 file changed, 111 insertions(+)
- `src/deep2/modelgenie/universal_gguf.cpp` | M | LIKELY_INTENDED_WIP |  1 file changed, 13 insertions(+)
- `src/deep2/op_gdn.cpp` | M | LIKELY_INTENDED_WIP |  1 file changed, 138 insertions(+), 1 deletion(-)
- `src/deep2/op_gdn.hpp` | M | LIKELY_INTENDED_WIP |  1 file changed, 18 insertions(+)
- `src/deep2/runtime_graph_executor.cpp` | M | LIKELY_INTENDED_WIP |  1 file changed, 132 insertions(+), 20 deletions(-)
- `src/deep2/shaders/deep2_qgemv.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `src/deep2/shaders/deep2_qwen4exp_gdn.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `src/deep2/shaders/deep2_qwen4exp_hc_combine.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `src/deep2/shaders/deep2_qwen4exp_moe_router.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `src/deep2/shaders/deep2_qwen4exp_ple.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `src/deep2/shaders/deep2_qwen4exp_qsa_score.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `src/deep2/vulkan_compute.cpp` | M | LIKELY_INTENDED_WIP |  1 file changed, 217 insertions(+), 17 deletions(-)
- `src/deep2/vulkan_compute.h` | M | LIKELY_INTENDED_WIP |  1 file changed, 23 insertions(+), 2 deletions(-)
- `src/win32app/Win32IDE_GhostText.cpp` | M | LIKELY_INTENDED_WIP |  1 file changed, 94 insertions(+), 9 deletions(-)
- `src/win32app/Win32IDE_GhostText.h` | M | LIKELY_INTENDED_WIP |  1 file changed, 4 insertions(+), 1 deletion(-)
- `src/win32app/Win32IDE_GhostTextIntegration.cpp` | M | LIKELY_INTENDED_WIP |  1 file changed, 46 insertions(+), 2 deletions(-)
- `tools/deep2_gpu_certify.cpp` | M | TOOL_NOT_PRODUCT |  1 file changed, 10 insertions(+), 3 deletions(-)
- `tools/deep2_qwen4exp_gdn_probe.cpp` | M | TOOL_NOT_PRODUCT |  1 file changed, 37 insertions(+), 6 deletions(-)
- `tools/deep2_qwen4exp_pipeline_probe.cpp` | M | TOOL_NOT_PRODUCT |  1 file changed, 1 insertion(+), 1 deletion(-)
- `tools/deep2_vulkan_gdn_dispatch_probe.cpp` | ?? | TOOL_NOT_PRODUCT | 
- `tools/llama_dump_logits_teacher_forced.cpp` | M | DRIFT_OR_UNKNOWN |  1 file changed, 11 insertions(+), 4 deletions(-)
- `tools/qwen36_gdn_cpu_parity.py` | ?? | DRIFT_OR_UNKNOWN | 
- `tools/shaders/quant_attn_decode.comp` | ?? | DRIFT_OR_UNKNOWN | 
- `tools/shaders/quant_attn_decode.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `tools/shaders/quant_dot_row4_q2k_specialized.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `tools/shaders/quant_dot_row4_q3k_specialized.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `tools/shaders/quant_dot_row4_q4k_specialized.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `tools/shaders/quant_dot_row4_q5k_specialized.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `tools/shaders/quant_dot_row4_q6k_specialized.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `tools/shaders/quant_dot_row8_q2k_specialized.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `tools/shaders/quant_dot_row8_q3k_specialized.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `tools/shaders/quant_dot_row8_q4k_specialized.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `tools/shaders/quant_dot_row8_q5k_specialized.spv` | ?? | DRIFT_OR_UNKNOWN | 
- `tools/shaders/quant_dot_row8_q6k_specialized.spv` | ?? | DRIFT_OR_UNKNOWN | 

## Next
1. Operator marks each LIKELY_INTENDED_WIP as KEEP_BRANCH / COMMIT / REVERT_TO_TIP
2. Then PRODUCT_BINARY_SEAL_001 for RawrXD-Win32IDE-Native from chosen clean tree
3. No debugger/swarm implementation until authority tree chosen
