#include "d2_nodep.h"

extern "C" int d2_packed_q2k_contract(uint64_t packed_bytes, uint64_t scratch_bytes, uint64_t materialized_weight_bytes) {
    if (!packed_bytes) return 0;
    if (materialized_weight_bytes != 0) return 0; // FULL_DEQUANT_BUFFER=0 / MATERIALIZED_WEIGHT_BYTES=0
    if (scratch_bytes > (64ull << 20)) return 0;  // bounded tile scratch, not model-sized scratch
    return 1;
}
