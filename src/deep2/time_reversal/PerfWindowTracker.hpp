// PerfWindowTracker.hpp — extended-duration rolling TPS windows
#pragma once
#include "TimeReversalTypes.hpp"
#include <cstdint>
#include <vector>

namespace Deep2 {
namespace TimeReversal {

struct TimedSample {
    uint64_t tMs = 0;       // monotonic sample time
    double decodeTps = 0.0;
    double msPerToken = 0.0;
    double decodeMs = 0.0;
    double wallMs = 0.0;
    uint64_t tokens = 0;
    double cpuBusyPct = 0.0;
    double gpu0BusyPct = 0.0;
    double gpu1BusyPct = 0.0;
    uint64_t ramBytes = 0;
    uint64_t gpu0VramBytes = 0;
    uint64_t gpu1VramBytes = 0;
    uint64_t nvmeBytes = 0;
    uint64_t workPresented = 0;
    uint64_t workExecuted = 0;
    uint64_t workAvoided = 0;
};

class PerfWindowTracker {
public:
    explicit PerfWindowTracker(size_t maxSamples = 65536);

    void Clear();
    void Record(const TimedSample& s);
    void RecordGeneration(uint64_t nowMs, const PerfGenerationRecord& g,
                          uint64_t workPresented, uint64_t workExecuted,
                          uint64_t workAvoided);

    PerfWindows Snapshot(uint64_t nowMs) const;

private:
    std::vector<TimedSample> samples_;
    size_t maxSamples_;
    PerfWindow Aggregate(uint64_t nowMs, uint64_t windowMs) const;
};

} // namespace TimeReversal
} // namespace Deep2
