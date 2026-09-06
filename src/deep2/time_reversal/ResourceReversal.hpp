// ResourceReversal.hpp — unused capacity → recoverable μs/token budget
#pragma once
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>

namespace Deep2 {
namespace TimeReversal {

struct ResourceSnapshot {
    double gpu0BusyPct = 0.0;
    double gpu1BusyPct = 0.0;
    double gpu0VramUsedMiB = 0.0;
    double gpu0VramTotalMiB = 0.0;
    double gpu1VramUsedMiB = 0.0;
    double gpu1VramTotalMiB = 0.0;
    double ramUsedMiB = 0.0;
    double ramTotalMiB = 0.0;
    double nvmeMiBps = 0.0;
    double nvmeCapMiBps = 0.0;
    double nvmeMsPerToken = 0.0; // measured storage share
};

struct ResourceOpportunity {
    double gpu0Headroom = 0.0; // 0..1
    double gpu1Headroom = 0.0;
    uint64_t ramHeadroomBytes = 0;
    uint64_t vram0HeadroomBytes = 0;
    uint64_t vram1HeadroomBytes = 0;
    double nvmeHeadroomMiBs = 0.0;
    double estimatedRecoverableUsPerToken = 0.0;
    char note[256]{};
};

inline double Clamp01(double x) {
    if (x < 0.0) return 0.0;
    if (x > 1.0) return 1.0;
    return x;
}

inline ResourceOpportunity DeriveResourceOpportunity(const ResourceSnapshot& s) {
    ResourceOpportunity o;
    o.gpu0Headroom = Clamp01(1.0 - s.gpu0BusyPct / 100.0);
    o.gpu1Headroom = Clamp01(1.0 - s.gpu1BusyPct / 100.0);
    const double ramFree = (std::max)(0.0, s.ramTotalMiB - s.ramUsedMiB);
    const double v0 = (std::max)(0.0, s.gpu0VramTotalMiB - s.gpu0VramUsedMiB);
    const double v1 = (std::max)(0.0, s.gpu1VramTotalMiB - s.gpu1VramUsedMiB);
    o.ramHeadroomBytes = static_cast<uint64_t>(ramFree * 1024.0 * 1024.0);
    o.vram0HeadroomBytes = static_cast<uint64_t>(v0 * 1024.0 * 1024.0);
    o.vram1HeadroomBytes = static_cast<uint64_t>(v1 * 1024.0 * 1024.0);
    o.nvmeHeadroomMiBs = (std::max)(0.0, s.nvmeCapMiBps - s.nvmeMiBps);

    // Conservative recoverable estimate from imbalance + storage share
    double us = 0.0;
    if (o.gpu0Headroom < 0.15 && o.gpu1Headroom > 0.40 && v1 > 4.0)
        us += 3500.0; // dual-GPU rebalance proxy
    if (ramFree > 8.0) us += 800.0;
    us += s.nvmeMsPerToken * 1000.0 * Clamp01(o.nvmeHeadroomMiBs / 1000.0) * 0.35;
    o.estimatedRecoverableUsPerToken = us;
    std::snprintf(o.note, sizeof(o.note),
        "gpu0_hr=%.2f gpu1_hr=%.2f ram_free=%.1fGiB v1_free=%.1fGiB",
        o.gpu0Headroom, o.gpu1Headroom, ramFree / 1024.0, v1);
    return o;
}

} // namespace TimeReversal
} // namespace Deep2
