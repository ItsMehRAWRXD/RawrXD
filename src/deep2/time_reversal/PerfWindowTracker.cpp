// PerfWindowTracker.cpp — rolling window aggregation
#include "PerfWindowTracker.hpp"
#include <algorithm>
#include <cmath>

namespace Deep2 {
namespace TimeReversal {

PerfWindowTracker::PerfWindowTracker(size_t maxSamples)
    : maxSamples_(maxSamples ? maxSamples : 65536) {
    samples_.reserve((std::min)(maxSamples_, size_t(4096)));
}

void PerfWindowTracker::Clear() { samples_.clear(); }

void PerfWindowTracker::Record(const TimedSample& s) {
    if (samples_.size() >= maxSamples_) {
        samples_.erase(samples_.begin(),
                       samples_.begin() + static_cast<std::ptrdiff_t>(maxSamples_ / 8));
    }
    samples_.push_back(s);
}

void PerfWindowTracker::RecordGeneration(uint64_t nowMs,
                                         const PerfGenerationRecord& g,
                                         uint64_t workPresented,
                                         uint64_t workExecuted,
                                         uint64_t workAvoided) {
    TimedSample s;
    s.tMs = nowMs;
    s.decodeTps = g.decodeTps;
    s.msPerToken = MsPerTokenFromTps(g.decodeTps);
    s.decodeMs = g.decodeWallMs;
    s.wallMs = g.totalWallMs;
    s.tokens = g.generatedTokens;
    s.cpuBusyPct = g.cpuBusyPct;
    s.gpu0BusyPct = g.gpu0BusyPct;
    s.gpu1BusyPct = g.gpu1BusyPct;
    s.ramBytes = static_cast<uint64_t>(g.ramPeakMiB * 1024.0 * 1024.0);
    s.gpu0VramBytes = static_cast<uint64_t>(g.gpu0VramMiB * 1024.0 * 1024.0);
    s.gpu1VramBytes = static_cast<uint64_t>(g.gpu1VramMiB * 1024.0 * 1024.0);
    s.nvmeBytes = static_cast<uint64_t>(g.nvmeReadMiB * 1024.0 * 1024.0);
    s.workPresented = workPresented;
    s.workExecuted = workExecuted;
    s.workAvoided = workAvoided;
    Record(s);
}

static void PercentileSorted(std::vector<double>& v, double p, double& out) {
    if (v.empty()) { out = 0.0; return; }
    std::sort(v.begin(), v.end());
    const double idx = p * static_cast<double>(v.size() - 1);
    const size_t i = static_cast<size_t>(idx);
    out = v[i];
}

PerfWindow PerfWindowTracker::Aggregate(uint64_t nowMs, uint64_t windowMs) const {
    PerfWindow w;
    std::vector<double> tps, mspt;
    for (const auto& s : samples_) {
        if (windowMs != 0 && nowMs >= windowMs && s.tMs + windowMs < nowMs)
            continue;
        w.generations++;
        w.tokens += s.tokens;
        w.wallMs += s.wallMs;
        w.decodeMs += s.decodeMs;
        w.cpuBusyPct += s.cpuBusyPct;
        w.gpu0BusyPct += s.gpu0BusyPct;
        w.gpu1BusyPct += s.gpu1BusyPct;
        w.ramPeakBytes = (std::max)(w.ramPeakBytes, s.ramBytes);
        w.gpu0VramPeakBytes = (std::max)(w.gpu0VramPeakBytes, s.gpu0VramBytes);
        w.gpu1VramPeakBytes = (std::max)(w.gpu1VramPeakBytes, s.gpu1VramBytes);
        w.nvmeBytes += s.nvmeBytes;
        w.workPresented += s.workPresented;
        w.workExecuted += s.workExecuted;
        w.workAvoided += s.workAvoided;
        if (s.decodeTps > 0.0) tps.push_back(s.decodeTps);
        if (s.msPerToken > 0.0) mspt.push_back(s.msPerToken);
    }
    if (w.generations == 0) return w;
    const double inv = 1.0 / static_cast<double>(w.generations);
    w.cpuBusyPct *= inv; w.gpu0BusyPct *= inv; w.gpu1BusyPct *= inv;
    double sumTps = 0.0;
    for (double x : tps) sumTps += x;
    w.meanTps = tps.empty() ? 0.0 : sumTps / static_cast<double>(tps.size());
    PercentileSorted(tps, 0.50, w.medianTps);
    PercentileSorted(tps, 0.05, w.p05Tps);
    PercentileSorted(tps, 0.95, w.p95Tps);
    double sumMs = 0.0;
    for (double x : mspt) sumMs += x;
    w.meanMsPerToken = mspt.empty() ? 0.0 : sumMs / static_cast<double>(mspt.size());
    PercentileSorted(mspt, 0.95, w.p95MsPerToken);
    PercentileSorted(mspt, 0.99, w.p99MsPerToken);
    return w;
}

PerfWindows PerfWindowTracker::Snapshot(uint64_t nowMs) const {
    PerfWindows out;
    out.last1s = Aggregate(nowMs, 1000);
    out.last10s = Aggregate(nowMs, 10000);
    out.last60s = Aggregate(nowMs, 60000);
    out.last5m = Aggregate(nowMs, 300000);
    out.last30m = Aggregate(nowMs, 1800000);
    out.session = Aggregate(nowMs, 0);
    return out;
}

} // namespace TimeReversal
} // namespace Deep2
