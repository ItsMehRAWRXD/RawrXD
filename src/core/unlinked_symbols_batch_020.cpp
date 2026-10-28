// unlinked_symbols_batch_020.cpp — REFERENCE ONLY (CMake COMMENT-OMIT on all lanes)
// ODR owner: MagBuf unlinked_symbols_batch_001.cpp
//   asm_perf_init / asm_perf_begin(uint32_t) / asm_perf_end(uint32_t,uint64_t) /
//   asm_perf_read_slot / asm_perf_reset_slot
// Prior slot-less asm_perf_begin(void)/end(uint64_t) signatures clash with MagBuf.
// Fail-closed: CMake omit — not #ifndef dual-link.
// PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0

namespace {
volatile int g_batch020_reference_anchor = 0;
}
