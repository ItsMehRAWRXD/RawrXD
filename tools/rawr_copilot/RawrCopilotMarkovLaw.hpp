#pragma once
/* RAWRXD_COPILOT_MARKOV_001 — sealed IDE product primitive (≠ Deep2). */
#define RAWRXD_COPILOT_MARKOV_001 1
#define PRODUCT_SURFACE_IDE_AUTOCOMPLETE 1
#define PRODUCT_PRIMITIVE_PARALLEL_TO_DEEP2 1
#define DEEP2_HOTPATH 0
#define DEEP2_REQUIRED_FOR_MARKOV 0
#define MARKOV_IS_MINIATURE_DEEP2 0
#define TRILLION_PARAMETER_NAMESPACE 1
#define TRILLION_PARAMETER_ALLOCATION 0
#define OBSERVED_TRANSITIONS_ONLY 1
#define MODEL_LOAD_ONCE 1
#define PERSISTENT_STDIO 1
#define NETWORK_REQUIRED 0
#define THIRD_PARTY_RUNTIME_REQUIRED 0
#define EDITOR_CONTEXT_IS_QUERY 1
#define GHOST_TEXT_IS_OUTPUT 1
#define TRAIN_COST_OUT_OF_BAND 1
#define MODEL_LOAD_COST_PER_COMPLETION 0
#define DECODE_LAYERS 0
#define QKV_WORK 0
#define KVA_WORK 0
#define TOKEN_LOOKUP_RESIDENT_OBSERVED 1
/*
  RawrCopilotMarkov = predictive IDE vocabulary / completion surface
  Deep2             = model execution / inference runtime
  RawrCopilotMarkov != miniature Deep2
  Deep2 != required for Markov completion

  LOGICAL_ADDRESS_SPACE != PHYSICAL_WORKING_SET
  LOGICAL_PARAMETER_SLOTS = 1_000_000_000_000 (addressable, not allocated)
  PHYSICAL_MODEL = observed transitions only

  EDITOR → cursor → resident stdio COMPLETE → RESULT/SCORE/END → ghost
  .rmc train out-of-band; completion = resident lookup only.

  Do not wire into lavapath / QKV / KVA / BgBmLaw / generateStream.
  Autocomplete may be replaced without reopening Deep2 certification.
*/
