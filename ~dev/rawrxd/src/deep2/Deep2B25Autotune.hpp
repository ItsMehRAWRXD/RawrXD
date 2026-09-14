#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace Deep2 {

struct TuneCandidate {
    uint32_t workgroup = 64;
    uint32_t vectorWidth = 4;
    uint32_t tileRows = 1;
    uint32_t tileCols = 256;
    uint32_t prefetch = 1;
    uint32_t gpu0Rows = 0;
    uint32_t gpu1Rows = 0;
};

struct TuneSample {
    TuneCandidate candidate{};
    double tps = 0.0;
    double bandwidthFraction = 0.0;
    double overlap = 0.0;
    double skew = 1.0;
    double hostSyncFraction = 1.0;
    uint64_t reloadBytes = 0;
    uint64_t hostMaterializations = 0;
    bool parity = false;
};

struct TuneGate {
    double minTps = 0.0;
    double minBandwidthFraction = 0.75;
    double minOverlap = 0.85;
    double maxSkew = 0.05;
    double maxHostSyncFraction = 0.03;
    uint64_t maxReloadBytes = 0;
    uint64_t maxHostMaterializations = 0;
};

struct TuneDecision {
    bool pass = false;
    size_t best = static_cast<size_t>(-1);
    const char* firstFailure = "NO_SAMPLES";
};

class B25Autotune {
public:
    static std::vector<TuneCandidate> enumerate(uint32_t totalRows);
    static TuneDecision choose(const std::vector<TuneSample>&, const TuneGate&) noexcept;
};

}
