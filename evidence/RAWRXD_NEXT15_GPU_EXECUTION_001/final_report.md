# RAWRXD_NEXT15_GPU_EXECUTION_001

- Build: PASS (`RawrXD-CLI-V2`, MSVC Release).
- Vulkan initialization: PASS; selected `AMD Radeon AI PRO R9700`.
- Production instrumentation: PASS; 20 successful queue submissions, 4 GPU GEMV operations, 1 completed layer.
- CPU fallbacks: 0; strict GPU violations: 0.
- Generation: BLOCKED; layer 0 prefill aborted on non-finite `blk.0.ffn_down.weight` input.
- Numerical parity: NOT_RUN because no comparable logits or token output was produced.
- Performance baseline: NOT_RUN because zero tokens were generated.
- Next repair boundary: investigate the layer-0 Q2_K/Q5_K FFN dequantization/input path; do not promote GPU or parity certification.

- CTest: PARTIAL; 4 tests passed, 15 tests unavailable or failed because their configured executables were not built in `build_ide`; this is separate from the production CLI smoke.
