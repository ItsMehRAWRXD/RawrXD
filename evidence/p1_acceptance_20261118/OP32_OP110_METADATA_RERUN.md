# Op 32 / Op 110 metadata and producer evidence

The pinned certifier was rerun only to retain metadata for the existing model
and token fixture. The independent reference directory and executable were
unchanged. No kernel or tolerance change was made.

MODEL=F:\\rawrxd\\models\\pdurugyan_qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2_latest.gguf
TOKENS=1,185
GPU_DEVICE=AMD Radeon AI PRO R9700

POS1_OP32_GPU=block3 pc32 op1 attn_norm weight=blk.3.attn_norm.weight input=<hidden> elements=4096 payload_sha256=7d50b3f360cde45e8830f2c79f046e56ea371287559080608ff47f592e59e109
POS1_OP32_CPU=block3 pc32 op1 attn_norm weight=blk.3.attn_norm.weight input=<hidden> elements=4096 payload_sha256=eec2c0e2372d1c2d7c60e641217be49b115722c008de6d0ba295d6b7ae65a4bd
POS1_OP31_GPU=block3 pc31 op16 resid_in input=<hidden> elements=4096 payload_sha256=52332ec2d8fc358d40200f7f66a8c34a58f17064020a8581b53094616d86a649
POS1_OP31_CPU=block3 pc31 op16 resid_in input=<hidden> elements=4096 payload_sha256=9757e60bcfa22788b32743a169e41004a9eef087289d9a38cf819d49f5cfe7fa
POS1_OP32_MAX_ABS=0.000347889959812
POS1_OP32_RMS=0.0000978433148148
POS1_OP32_COSINE=0.999999996821

POS0_OP110_GPU=block10 pc110 op1 attn_norm weight=blk.10.attn_norm.weight input=<hidden> elements=4096 payload_sha256=6b858960074abf7b02a1a417d20cd50b7b6e6a0b0ed4029d5aa9810d98d42708
POS0_OP110_CPU=block10 pc110 op1 attn_norm weight=blk.10.attn_norm.weight input=<hidden> elements=4096 payload_sha256=06b938d3776213d7a5275fb13125d460eb38a1cfd86a7427accee821e7de21fc
POS0_OP109_GPU=block10 pc109 op16 resid_in input=<hidden> elements=4096 payload_sha256=47ead3a301f86d544a02a1e2edb34be2b8736893de2e343112019cac6d9742a3
POS0_OP109_CPU=block10 pc109 op16 resid_in input=<hidden> elements=4096 payload_sha256=ea09f33d064ba585644355879555e633b7b833f8fb363eac88ddc93c0e50f292
POS0_OP110_MAX_ABS=0.00015914440155
POS0_OP110_RMS=0.0000466436875362
POS0_OP110_COSINE=0.999999998902

CAUSAL_CONCLUSION=Both threshold crossings inherit differing resid_in tensors; neither attention RMSNorm node is proven causal.
INPUT_TENSOR_NAME=<hidden> only; producer payload hashes retained.
FIRST_CAUSAL_OPERATOR=Still unknown; trace must continue backward from op31/op109.
