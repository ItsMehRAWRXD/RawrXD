#include "d2_nodep.h"

extern "C" int d2_packed_q4k_contract(uint64_t packed_bytes, uint64_t scratch_bytes, uint64_t materialized_weight_bytes) {
    if (!packed_bytes) return 0;
    if (materialized_weight_bytes != 0) return 0;
    if (scratch_bytes > (96ull << 20)) return 0;
    return 1;
}
