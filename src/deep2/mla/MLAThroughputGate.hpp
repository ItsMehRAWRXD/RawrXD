#pragma once
#include <cstdint>
#include <cmath>
namespace rawrxd::mla {
struct PerformanceSample {
    uint64_t committedTokens = 0, elapsedNs = 0;
    uint64_t gpu0Completed = 0, gpu1Completed = 0;
    uint64_t overlapNs = 0, unexpectedCpuFallbacks = 0;
    bool parityPassed = false;
    bool calibratedTimestamps = false;
    double tps() const noexcept {
        if (!elapsedNs) return 0.0;
        return double(committedTokens) * 1.0e9 / double(elapsedNs);
    }
};
struct PerformanceVerdict {
    bool passed = false;
    double baselineTps = 0.0, dualTps = 0.0, speedup = 0.0;
};
inline PerformanceVerdict certifyPerformance(const PerformanceSample& baseline, const PerformanceSample& dual, double requiredSpeedup) {
    PerformanceVerdict result;
    result.baselineTps = baseline.tps();
    result.dualTps = dual.tps();
    if (!std::isfinite(requiredSpeedup) || requiredSpeedup <= 1.0 ||
        !baseline.parityPassed || !dual.parityPassed ||
        !baseline.committedTokens || baseline.committedTokens != dual.committedTokens ||
        !baseline.elapsedNs || !dual.elapsedNs ||
        !dual.gpu0Completed || !dual.gpu1Completed ||
        !dual.calibratedTimestamps || !dual.overlapNs || dual.overlapNs > dual.elapsedNs ||
        baseline.unexpectedCpuFallbacks || dual.unexpectedCpuFallbacks ||
        result.baselineTps <= 0.0) return result;
    result.speedup = result.dualTps / result.baselineTps;
    result.passed = result.speedup >= requiredSpeedup;
    return result;
}
}