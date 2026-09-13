/* DualStickImbalance_Xfer.cpp — TIER1 + DIAG #7–#11. ≤99. */
#include "DualStickImbalance_Xfer.hpp"

namespace Deep2 {
namespace ds_imb {

static const uint64_t kSeedNpm = 131072ull; /* ~8 GB/s */
static const uint64_t kSeedFix = 200000ull;
static const uint64_t kSeedQ = 50000ull;

uint64_t g_queueDelay[2] = {kSeedQ, kSeedQ};
uint32_t g_queueN[2] = {0, 0};
uint64_t g_startupNs[2][XFER_BUCKETS] = {
    {kSeedFix, kSeedFix, kSeedFix, kSeedFix},
    {kSeedFix, kSeedFix, kSeedFix, kSeedFix}};
uint64_t g_soloNpm[2][XFER_BUCKETS] = {
    {kSeedNpm, kSeedNpm, kSeedNpm, kSeedNpm},
    {kSeedNpm, kSeedNpm, kSeedNpm, kSeedNpm}};
uint64_t g_dualNpm[2][XFER_BUCKETS] = {
    {kSeedNpm + (kSeedNpm >> 2), kSeedNpm + (kSeedNpm >> 2),
     kSeedNpm + (kSeedNpm >> 2), kSeedNpm + (kSeedNpm >> 2)},
    {kSeedNpm + (kSeedNpm >> 2), kSeedNpm + (kSeedNpm >> 2),
     kSeedNpm + (kSeedNpm >> 2), kSeedNpm + (kSeedNpm >> 2)}};
uint32_t g_soloN[2][XFER_BUCKETS] = {};
uint32_t g_dualN[2][XFER_BUCKETS] = {};
uint32_t g_layerMiss[2] = {0, 0};
uint64_t g_fabricPen = 0;
uint32_t g_fabricN = 0;
uint64_t g_dualSlowMulX100 = 125ull; /* 1.25× when overlap */

void XferBeginLayer() { g_layerMiss[0] = g_layerMiss[1] = 0; }
void XferNoteMiss(unsigned stick) { g_layerMiss[stick & 1u]++; }
uint64_t QueueDelayNs(unsigned stick) { return g_queueDelay[stick & 1u]; }

static void EwmaU64(uint64_t& slot, uint32_t& n, uint64_t sample) {
    if (n < 4u) slot = (slot + sample) / 2ull;
    else slot = (slot * 7ull + sample) / 8ull;
    n++;
}

uint64_t TransferExecNs(unsigned stick, uint64_t bytes) {
    stick &= 1u;
    const unsigned b = SizeBucket(bytes);
    const int dual = (g_layerMiss[0] && g_layerMiss[1]) ? 1 : 0;
    uint64_t npm = dual ? g_dualNpm[stick][b] : g_soloNpm[stick][b];
    uint64_t ns = g_startupNs[stick][b];
    if (bytes) ns += (bytes * npm) >> 20;
    if (dual) ns = (ns * g_dualSlowMulX100) / 100ull; /* #10 */
    return ns;
}

uint64_t TransferNs(unsigned stick, uint64_t bytes) {
    stick &= 1u;
    uint64_t ns = g_queueDelay[stick] + TransferExecNs(stick, bytes);
    if (g_layerMiss[0] && g_layerMiss[1]) ns += g_fabricPen; /* saturation */
    return ns;
}

void XferObserveSplit(unsigned stick, uint64_t bytes, uint64_t queueNs,
                      uint64_t execNs, int dualActive) {
    stick &= 1u;
    if (queueNs) {
        if (queueNs < (kSeedQ >> 3)) queueNs = kSeedQ >> 3;
        if (queueNs > (kSeedQ << 4)) queueNs = kSeedQ << 4;
        EwmaU64(g_queueDelay[stick], g_queueN[stick], queueNs);
    }
    if (!bytes || !execNs) return;
    const unsigned b = SizeBucket(bytes);
    uint64_t startup = g_startupNs[stick][b];
    uint64_t body = (execNs > startup) ? (execNs - startup) : (execNs / 2ull);
    if (body < startup / 4ull) {
        EwmaU64(g_startupNs[stick][b], g_soloN[stick][b], execNs);
        return;
    }
    uint64_t npm = (body << 20) / bytes;
    if (npm < (kSeedNpm >> 3)) npm = kSeedNpm >> 3;
    if (npm > (kSeedNpm << 3)) npm = kSeedNpm << 3;
    if (dualActive) {
        EwmaU64(g_dualNpm[stick][b], g_dualN[stick][b], npm);
        /* learn slowdown vs solo */
        uint64_t solo = g_soloNpm[stick][b] ? g_soloNpm[stick][b] : kSeedNpm;
        uint64_t mul = (npm * 100ull) / solo;
        if (mul < 100ull) mul = 100ull;
        if (mul > 400ull) mul = 400ull;
        g_dualSlowMulX100 = (g_dualSlowMulX100 * 7ull + mul) / 8ull;
        g_fabricPen =
            g_fabricN ? (g_fabricPen * 7ull + (execNs >> 3)) / 8ull
                      : (execNs >> 3);
        g_fabricN++;
    } else {
        EwmaU64(g_soloNpm[stick][b], g_soloN[stick][b], npm);
    }
}

} // namespace ds_imb
} // namespace Deep2
