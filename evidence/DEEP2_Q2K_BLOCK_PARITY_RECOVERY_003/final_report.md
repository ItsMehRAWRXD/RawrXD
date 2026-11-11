DEEP2_Q2K_BLOCK_PARITY_RECOVERY_003
Storage geometry: PASS
Generic Vulkan probe: PASS for IQ2_S/MXFP4 only
Production Q2_K GPU output: FAIL with 6963 NaNs
Block decode comparison: NOT_RUN
Certification: BLOCKED
Real-weight Vulkan Q2_K quant-dot: PASS against GGML reference (cosine 1.0, rel 1.584e-7, max abs 1.164e-9). Existing independent integer-lane cross-check failed and requires separate repair. This does not certify the production deep2_qgemv FFN path, which remains non-finite.
