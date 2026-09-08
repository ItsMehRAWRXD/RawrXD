#pragma once
/* Foundation ladder: base forward sits above addressability, below capability. */
#define RAWR_F_ABI (-3)
#define RAWR_F_MODEL_FACTS (-2)
#define RAWR_F_EXEC_INSTANCE (-1)
#define RAWR_F_ADDRESSABILITY 0
#define RAWR_F_BASE_FORWARD 1
#define RAWR_F_CAPABILITY 2
#define RAWR_F_LIVE_SPACE 3
#define RAWR_F_SHAPE_SOLVER 4
#define RAWR_F_MEASUREMENT 5
#define RAWR_F_OPTIONAL_CHOREOGRAPHY 6
#define RAWR_F_PRODUCT 7

#define HOST_DECODE_SKIP_LIVEPATH_MEANS_SKIP_ENHANCEMENTS_ONLY 1
#define HOST_DECODE_SKIP_LIVEPATH_MEANS_SKIP_BASE_FORWARD 0
#define REGISTERED_BYTES_NE_RESIDENT_BYTES 1

/*
  BASE DECODE TOPOLOGY (structurally unavoidable):
    embed → every layer → final norm → logits
  OPTIONAL (skippable): elastic, cyclone, ckv, medusa, prefetch, livepath
  NEVER: embed → logits
*/
