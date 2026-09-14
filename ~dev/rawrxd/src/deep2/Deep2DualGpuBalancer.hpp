#pragma once
#include "Deep2RooflineCommon.hpp"

namespace Deep2::Roofline {

class DualGpuBalancer {
public:
    struct Config {
        double ewmaAlpha = 0.20;
        double minFraction = 0.10;
        double maxFraction = 0.90;
        u32 rowGranularity = 32;
    };

    DualGpuBalancer() = default;
    explicit DualGpuBalancer(Config c) : cfg_(c) {}
    void reset() noexcept;
    void update(unsigned gpu, const DeviceSample& sample) noexcept;
    SplitPlan plan(u32 totalRows) const noexcept;
    double rate(unsigned gpu) const noexcept { return gpu < 2 ? rate_[gpu] : 0.0; }

private:
    Config cfg_{};
    double rate_[2]{0.0, 0.0}; // EWMA work units / ns
};

} // namespace Deep2::Roofline
