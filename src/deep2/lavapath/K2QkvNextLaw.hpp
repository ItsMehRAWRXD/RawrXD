#pragma once
/* K2_QKV_NEXT_001 — product-directed wall cut, not internal-counter green. */
#define K2_QKV_NEXT_001 1
#define K2_QKV_NEXT_WALL_NS_TARGET 17000000000ull
#define K2_QKV_NEXT_QKV_FRAC 0.80
#define PRODUCT_WALL_BUDGET_NS_64TOK 12800000000ull

/*
  PASS iff:
    QKV_NUMERIC_PARITY=1
    CPU_F32_EXPANDS=0
    HOST_FORWARD_LAYER_CALLS=0
    AND ( GENERATION_WALL_NS < 17.0e9
          OR QKV_PROJ_US <= 0.80 * baseline )

  Ladder:
    tag1/2 ROWS climb (argmin wall among legal+parity)
      → KVA shared-x
      → re-rank QKV
      → stage fusion if wall still >~17s

  KVA_SHARED_X invariant: x tile once/WG, not once/row.
*/
