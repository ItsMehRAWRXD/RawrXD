#pragma once
/* #13 TIER1 transfer finish model + DIAG #7–#11. ≤99. */
#include <cstdint>

namespace Deep2 {
namespace ds_imb {

enum { XFER_BUCKETS = 4 };

extern uint64_t g_queueDelay[2];              /* #9 enqueue→start EWMA */
extern uint32_t g_queueN[2];
extern uint64_t g_startupNs[2][XFER_BUCKETS]; /* fixed launch/startup */
extern uint64_t g_soloNpm[2][XFER_BUCKETS];   /* #11 solo BW ns/MiB */
extern uint64_t g_dualNpm[2][XFER_BUCKETS];   /* #11 dual-active BW */
extern uint32_t g_soloN[2][XFER_BUCKETS];
extern uint32_t g_dualN[2][XFER_BUCKETS];
extern uint32_t g_layerMiss[2];
extern uint64_t g_fabricPen; /* shared_fabric_penalty_ns EWMA */
extern uint32_t g_fabricN;
extern uint64_t g_dualSlowMulX100; /* #10 overlap slowdown ×100 (100=1.0) */

inline unsigned SizeBucket(uint64_t bytes) {
    if (bytes < (1ull << 20)) return 0u;
    if (bytes < (8ull << 20)) return 1u;
    if (bytes < (32ull << 20)) return 2u;
    return 3u;
}

void XferBeginLayer();
void XferNoteMiss(unsigned stick);
/* #8: feed ONLY exec (start→finish) into BW; queue separate. */
void XferObserveSplit(unsigned stick, uint64_t bytes, uint64_t queueNs,
                      uint64_t execNs, int dualActive);
uint64_t TransferNs(unsigned stick, uint64_t bytes); /* finish contrib */
uint64_t TransferExecNs(unsigned stick, uint64_t bytes); /* no queue */
uint64_t QueueDelayNs(unsigned stick);

} // namespace ds_imb
} // namespace Deep2
