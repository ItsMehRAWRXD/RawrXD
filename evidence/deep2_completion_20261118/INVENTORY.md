# Deep2 completion inventory

GIT_SHA=49ab4ee1d8ae9800ab4c6b458a0761c3489ece31
BRANCH=evidence/reap-multi-model-20261113
DIRTY_STATUS_ENTRIES=238
PROMOTE=0
CERTIFIED=0
RELEASE=HELD

The worktree contains unrelated and in-progress changes. No cleanup or reset
was performed.

Known real model artifacts include Qwen3.5, DeepSeek Coder V2, DeepSeek R1,
GPT-OSS, Nemotron, Kimi and Qwen2.5 GGUF files. Vulkan device enumeration is
available in the environment; prior retained runtime evidence identifies the
AMD Radeon AI PRO R9700 and AMD Radeon RX 7800 XT.

## Current evidence classification

REFERENCE_PARITY=FAIL
GPU_CPU_PARITY=FAIL
REAP_ZERO_STANDALONE_MLA=PASS_REPORTED
Q6K_IDENTICAL_INPUT_KERNEL_DEFECT=NOT_SUPPORTED
MARS_VULKAN_COEXISTENCE=REPORTED_PASS
MARS_LIVE_MIGRATION=NOT_TESTED
CYCLONE_FULL_RUNTIME=NOT_TESTED
GPU_MOE_PARITY=NOT_TESTED
MULTI_GPU_CORRECTNESS=NOT_TESTED
SSM_MAMBA_END_TO_END=NOT_TESTED
SOVEREIGN_END_TO_END=NOT_TESTED
NATIVE_EXECUTOR_CTEST=PASS
FULL_DEEP2_CERTIFICATION=HELD
