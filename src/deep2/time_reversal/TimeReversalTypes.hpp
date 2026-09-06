// TimeReversalTypes.hpp — TPS/utilization physical measurement types
#pragma once
#include <cstdint>
#include <cstring>

namespace Deep2 {
namespace TimeReversal {

struct Hash256 {
    uint8_t b[32]{};
    bool operator==(const Hash256& o) const { return std::memcmp(b, o.b, 32) == 0; }
};

// Per-generation physical counters (authoritative observation)
struct PerfGenerationRecord {
    uint64_t promptTokens = 0;
    uint64_t generatedTokens = 0;
    double ttftMs = 0.0;
    double decodeWallMs = 0.0;
    double totalWallMs = 0.0;

    double promptTps = 0.0;
    double decodeTps = 0.0;
    double endToEndTps = 0.0;

    double cpuBusyPct = 0.0;
    double ramWorkingSetMiB = 0.0;
    double ramPeakMiB = 0.0;
    double gpu0VramMiB = 0.0;
    double gpu1VramMiB = 0.0;
    double gpu0BusyPct = 0.0;
    double gpu1BusyPct = 0.0;

    double nvmeReadMiB = 0.0;
    double nvmeReadMiBps = 0.0;
    double weightsLoadedMiB = 0.0;
    double weightsReusedMiB = 0.0;
    double kvMiB = 0.0;

    uint64_t stateGeneration = 0;
    Hash256 stateImageSha{};
    Hash256 policySha{};
    Hash256 rulesetSha{};
};

// Per-token physical cost ledger (μs)
struct TokenTimeLedger {
    double embeddingUs = 0.0;
    double weightAcquireUs = 0.0;
    double nvmeWaitUs = 0.0;
    double ramStageUs = 0.0;
    double gpuTransferUs = 0.0;
    double attentionUs = 0.0;
    double ropeUs = 0.0;
    double softmaxUs = 0.0;
    double kvReadUs = 0.0;
    double kvWriteUs = 0.0;
    double ffnGateUs = 0.0;
    double ffnUpUs = 0.0;
    double ffnDownUs = 0.0;
    double moeRouteUs = 0.0;
    double expertLoadUs = 0.0;
    double expertComputeUs = 0.0;
    double logitsUs = 0.0;
    double samplingUs = 0.0;
    double verificationUs = 0.0;
    double schedulerUs = 0.0;
    double synchronizationUs = 0.0;
    double totalUs = 0.0; // measured wall for this token
};

struct PerfWindow {
    uint64_t tokens = 0;
    uint64_t generations = 0;
    double wallMs = 0.0;
    double decodeMs = 0.0;
    double meanTps = 0.0;
    double medianTps = 0.0;
    double p05Tps = 0.0;
    double p95Tps = 0.0;
    double meanMsPerToken = 0.0;
    double p95MsPerToken = 0.0;
    double p99MsPerToken = 0.0;
    double cpuBusyPct = 0.0;
    double gpu0BusyPct = 0.0;
    double gpu1BusyPct = 0.0;
    uint64_t ramPeakBytes = 0;
    uint64_t gpu0VramPeakBytes = 0;
    uint64_t gpu1VramPeakBytes = 0;
    uint64_t nvmeBytes = 0;
    uint64_t workPresented = 0;
    uint64_t workExecuted = 0;
    uint64_t workAvoided = 0;
};

struct PerfWindows {
    PerfWindow last1s;
    PerfWindow last10s;
    PerfWindow last60s;
    PerfWindow last5m;
    PerfWindow last30m;
    PerfWindow session;
};

inline double MsPerTokenFromTps(double tps) {
    return (tps > 0.0) ? (1000.0 / tps) : 0.0;
}
inline double TpsFromMsPerToken(double ms) {
    return (ms > 0.0) ? (1000.0 / ms) : 0.0;
}

} // namespace TimeReversal
} // namespace Deep2
