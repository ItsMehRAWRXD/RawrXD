RAWRXD_Q4K_GEMV_PARITY_001 -- oracle run, cols=256 (single Q4_K block per row)

HARNESS_COMPILE=PASS (CL_EXIT=0)
HARNESS_LINK=PASS   (LINK_EXIT=0, objects: q4k_gemv_parity, vulkan_compute, QuantKernelRegistry)
GPU_REAL_EXECUTION=1 (Vulkan device init OK, real dispatch, real readback)

CASE_A synthetic_q4k  rows=256 cols=256 bytes=36864
  REF_DOUBLE_0_8   = 0.0059354 0.00910897 0.00675024 0.00651552 0.00463027 0.00601978 0.00754599 0.00720937
  GPU_OUT_0_8       = 0.0118708 0.0182179 0.0135005 0.013031 0.00926054 0.0120396 0.015092 0.0144187
  RATIO_GPU_OVER_REF= 2.000000 2.000000 2.000000 2.000000 2.000000 2.000000 2.000000 2.000000

  MAX_ABS_ERR        = 0.0136029366
  SUM_ABS_TERMS      = 0.0136029364
  REL_TO_TERMS       = 1
  FP32_BUDGET        = 2.93823426e-07
  ARGMAX_CPU         = 189
  ARGMAX_GPU         = 189

  ORACLE:
    DOUBLE_VS_LINEAR = 3.7252903e-09
    DOUBLE_VS_TREE   = 9.31322575e-10
    LINEAR_VS_TREE   = 3.7252903e-09
    TREE_VS_GPU      = 0.0136029366
    DOUBLE_VS_GPU    = 0.0136029366
    LINEAR_VS_GPU    = 0.0136029376
    TREE_MAX         = 0.0136029366

  ORDER_EXPLAINS_MISMATCH       = 0
  TREE_IS_AUTHORITATIVE         = 1
  DATA_INTERPRETATION_DEFECT    = 1
  PARITY                        = FAIL

CASE_C synthetic_q6k  rows=256 cols=256 bytes=53760
  REF_DOUBLE_0_8   = 13.6605 (all rows identical by construction)
  GPU_OUT_0_8       = 13.6606
  MAX_ABS_ERR       = 0
  ORACLE TREE_VS_GPU= 0
  ORDER_EXPLAINS_MISMATCH    = 1
  DATA_INTERPRETATION_DEFECT = 0
  PARITY                     = PASS

CASE_B real_model_wk = NOT_RUN (no model arg supplied)

VERDICT=INCONCLUSIVE_CASE_B_NOT_RUN
Q4K_SYNTHETIC_GEMV=FAIL
Q6K_SYNTHETIC_GEMV=PASS
Q4K_DATA_INTERPRETATION_DEFECT=1
SUMMATION_ORDER_EXPLAINS_MISMATCH=0

---- FALSIFICATION RESULT (predicted before the run) ----
PREDICTED DOUBLE_VS_TREE = tiny        OBSERVED 9.31e-10      CONFIRMED
PREDICTED TREE_VS_GPU    = large       OBSERVED 1.36e-02      CONFIRMED

---- SUPERFICIAL ATTRIBUTE OF THE DEFECT ----
The failure is NOT a generic scale/min/nibble misinterpretation. The GPU result is
exactly 2x the reference on all 8 sampled rows and on the argmax row:
    MAX_ABS_ERR = 0.0136029366
    TREE_MAX    = 0.0136029366
If GPU = 2 * REF pointwise then |GPU - REF| = |REF| and the max absolute delta
equals the max absolute reference value exactly, which is what is observed.
This is a systematic FACTOR-OF-TWO, not noise, not drift, not cancellation.

Also note ARGMAX_CPU == ARGMAX_GPU == 189, so the sign/lane/ordering of the
product is correct; only the magnitude is doubled.

Q6_K passing with the identical input, descriptor layout, dispatch geometry,
push constants and upload path isolates the defect to the Q4_K dequant arm
specifically, and rules out the shared GEMV plumbing.

SUSPECTED_MECHANISM (unproven, requires shader read):
  Q4_K packs 256 values per 144-byte block. A 2x consistent scale is consistent
  with the shader emitting each product twice, accumulating two halves into one
  register, or reading a doubled d/dmin pair. Must be confirmed in the SPIR-V
  dequant arm, not assumed.

LOG = F:\~dev\rawrxd\audit\RAWRXD_Q4K_GEMV_PARITY_001\oracle_cols256.log
