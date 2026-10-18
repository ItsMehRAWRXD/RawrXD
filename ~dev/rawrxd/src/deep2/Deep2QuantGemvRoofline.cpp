#include "Deep2QuantGemvRoofline.hpp"

namespace Deep2 {

QuantGemvPlan QuantGemvRoofline::plan(const QuantGemvShape& s,
                                      const DeviceRoofline& d) noexcept {
    QuantGemvPlan p{};
    const uint32_t wave = d.waveWidth ? d.waveWidth : 64;
    p.workgroupSize = (wave >= 64) ? 256u : 128u;
    if (s.cols < 2048) p.workgroupSize = 128;
    if (s.cols < 1024) p.workgroupSize = 64;

    p.vectorWidth = (s.quantBits <= 4 && (s.cols % 8u) == 0u) ? 8u : 4u;
    p.colsPerLane = p.vectorWidth;
    p.rowsPerGroup = s.rows >= 8192 ? 4u : (s.rows >= 2048 ? 2u : 1u);

    // Larger prefetch distance for bandwidth-bound, long rows.
    p.prefetchBlocks = s.cols >= 8192 ? 4u : (s.cols >= 4096 ? 3u : 2u);
    p.fuseDequantDot = true;
    p.useSubgroupReduce = wave == 32 || wave == 64;
    return p;
}

double QuantGemvRoofline::arithmeticIntensity(const QuantGemvShape& s) noexcept {
    if (!s.rows || !s.cols) return 0.0;
    const double weightBytes =
        double(s.rows) * double(s.cols) * (double(s.quantBits) / 8.0);
    const double scaleBytes =
        double(s.rows) * std::ceil(double(s.cols) / double(s.groupSize)) * 4.0;
    const double ioBytes = double(s.cols + s.rows) * 4.0;
    const double flops = 2.0 * double(s.rows) * double(s.cols);
    return flops / (weightBytes + scaleBytes + ioBytes);
}

double QuantGemvRoofline::theoreticalTokensPerSecond(uint64_t bytesPerToken,
                                                      double effectiveBandwidthGBs) noexcept {
    if (!bytesPerToken || effectiveBandwidthGBs <= 0.0) return 0.0;
    return effectiveBandwidthGBs * 1.0e9 / double(bytesPerToken);
}

} // namespace Deep2
