# Q6_K identical-input negative result

This receipt records the supplied isolated test. It does not certify the
full model and does not justify a Q6_K kernel change.

TENSOR=blk.2.ffn_down.weight
TYPE=Q6_K(14)
SHAPE=4096x12288
INPUT_IDENTITY=EXACT
INHERITED_INPUT_MAX_ABS=0
GPU_VS_F64_COSINE=0.999741682
CPU_VS_F64_COSINE=0.999741744
GPU_VS_F64_RMS=0.00242947
CPU_VS_F64_RMS=0.00242918
GPU_VS_CPU_COSINE=0.999999985
GPU_VS_CPU_MAX_ABS=0.0000638
GPU_VS_CPU_RMS=0.0000184

KERNEL_DEFECT=NOT_SUPPORTED_BY_THIS_TEST
BOTH_KERNELS_EQUALLY_ACCURATE=REPORTED
TOOL_VERDICT_LABEL=INVALIDATED_BY_THRESHOLD_LOGIC
FULL_LOGIT_ROOT_CAUSE=UNRESOLVED
GPU_CPU_PARITY=FAIL
INDEPENDENT_REFERENCE_PARITY=FAIL

Next diagnostic: compare Deep2 CPU against the pinned llama.cpp reference at
early layer boundaries to distinguish shared semantic differences from
accumulated CPU/GPU arithmetic differences.
