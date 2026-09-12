/*
  Integration sketch only: bind these callbacks to the already-live Deep2
  packed Q2_K operator and compact reducer. Do NOT substitute probe traffic.
*/
#include "../include/d2_material_overlap.h"

struct Deep2PackedCtx {
    /* Product-owned tensor view / dispatch state goes here. */
    uint64_t exact_local_bytes;
};

static int32_t D2_CALL record_real_q2k(void* u, D2VkCommandBuffer cmd,
                                       uint64_t token, uint64_t op,
                                       uint64_t* packed_bytes) {
    Deep2PackedCtx* c = (Deep2PackedCtx*)u;
    if (!c || !cmd || !packed_bytes) return -1;
    /*
      CALL YOUR REAL PRODUCT RECORDER HERE, e.g.
        Deep2RecordPackedQ2KLocalRows(c, cmd, token, op);
      It must bind the real packed GGUF device-local tensor view directly.
      No host dequant buffer and no synthetic dispatch are permitted.
    */
    *packed_bytes = c->exact_local_bytes;
    return -999; /* fail closed until replaced by the real product call */
}

static int32_t D2_CALL compact_reduce_real(void* u, uint64_t token, uint64_t op,
                                            uint64_t* bytes, uint32_t* real) {
    (void)u; (void)token; (void)op;
    if (!bytes || !real) return -1;
    /* Bind existing Deep2 compact reducer here. */
    *bytes = 0; *real = 0;
    return -999; /* fail closed until product bound */
}

/*
  Suggested policy for the authority gate:
    min_shorter_overlap_permille = 700
    min_critical_overlap_permille = 500
    max_calibration_deviation_ns = 50000
    min_packed_bytes_per_lane = 1 MiB (or operator-specific floor)
*/
