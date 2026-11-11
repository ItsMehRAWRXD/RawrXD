#include "rawrxd/src/deep2/Deep2QuantGemvRoofline.hpp"
#include "rawrxd/src/deep2/Deep2WaveOccupancy.hpp"
#include "rawrxd/src/deep2/Deep2KvMlaTraffic.hpp"
#include "rawrxd/src/deep2/Deep2MoEMathPlan.hpp"
#include "rawrxd/src/deep2/Deep2LaunchAmortizer.hpp"
#include "rawrxd/src/deep2/Deep2RooflineRatchet.hpp"
#include <cstdio>
#include <vector>

using namespace Deep2;

static int fail(const char* s) {
    std::printf("FAIL=%s\n", s);
    return 1;
}

int main() {
    DeviceRoofline r9700{640.0, 0.0, 64, 64, 32ull<<30};
    DeviceRoofline rx7800{624.0, 0.0, 60, 64, 16ull<<30};

    QuantGemvShape shape{8192, 8192, 4, 32};
    auto q0 = QuantGemvRoofline::plan(shape, r9700);
    auto q1 = QuantGemvRoofline::plan(shape, rx7800);
    if (!q0.fuseDequantDot || q0.workgroupSize < 64) return fail("B16_QGEMV");

    OccupancyInput oi{};
    oi.totalRows = 8192;
    oi.regsPerThread = 56;
    oi.sharedBytesPerGroup = 8192;
    oi.recentGpu0NsPerRow = 100.0;
    oi.recentGpu1NsPerRow = 110.0;
    auto occ = WaveOccupancyScheduler::make(oi, r9700, rx7800);
    if (occ.gpu0Rows + occ.gpu1Rows != oi.totalRows) return fail("B17_SPLIT");

    KvMlaInput ki{};
    ki.context = 32768;
    ki.heads = 64;
    ki.qkNopeDim = 128;
    ki.qkRopeDim = 64;
    ki.vDim = 128;
    ki.kvLoraRank = 512;
    ki.bytesPerScalar = 2;
    ki.useMLA = true;
    auto kv = KvMlaTrafficReducer::plan(ki);
    if (!kv.keepCompressedKv || !kv.fuseGatherDot) return fail("B18_MLA");

    std::vector<RoutedExpert> ex = {
        {1, .55f, 0, 1, 9000.0},
        {2, .30f, 1, 1, 7000.0},
        {3, .15f, 0, 0, 12000.0}
    };
    auto moe = MoEExpertMathPlanner::make(ex);
    if (moe.ordered.empty() || !moe.fuseGateUp) return fail("B19_MOE");

    auto batches = LaunchAmortizer::build(true, true);
    if (batches.size() != 2 || !batches[0].oneSubmit) return fail("B19_BATCH");

    DecodeSample d{};
    d.tokenNs = 20'000'000;
    d.gpu0Ns = 18'000'000;
    d.gpu1Ns = 17'300'000;
    d.overlapNs = 16'000'000;
    d.hostSyncNs = 500'000;
    d.weightReloadBytes = 0;
    d.hostMaterializations = 0;
    d.parity = true;

    KernelSample ks{};
    // 900 GB/s measured over 10 ms = 9 GB transferred.
    ks.bytesRead = 8'500'000'000ull;
    ks.bytesWritten = 500'000'000ull;
    ks.durationNs = 10'000'000;

    auto state = RooflineRatchet::measure(d, ks, 1264.0);
    RooflineTargets target{};
    target.minBandwidthFraction = 0.70;
    target.minOverlapRatio = 0.80;
    target.maxCompletionSkew = 0.05;
    target.maxHostSyncFraction = 0.05;
    auto cert = RooflineRatchet::certify(state, target);
    if (!cert.pass) return fail(cert.firstFailure);

    std::printf("DEEP2_BATCH16_20_SELFTEST=PASS\n");
    std::printf("B16_QGEMV_WG=%u\n", q0.workgroupSize);
    std::printf("B17_ROWS=%u/%u\n", occ.gpu0Rows, occ.gpu1Rows);
    std::printf("B18_MLA_BYTES_EST=%llu\n", (unsigned long long)kv.estimatedBytesPerToken);
    std::printf("B19_EXPERTS=%zu\n", moe.ordered.size());
    std::printf("B20_BW_FRACTION=%.6f\n", state.bandwidthFraction);
    std::printf("B20_OVERLAP=%.6f\n", state.overlapRatio);
    std::printf("B20_SKEW=%.6f\n", state.completionSkew);
    std::printf("B20_CERT=%s\n", cert.firstFailure);
    return 0;
}
