#pragma once
#include <cstdint>
#include <vector>
#include <algorithm>
#include <mutex>
#include <unordered_map>
namespace rawrxd::mla {
struct Interval { uint64_t begin = 0; uint64_t end = 0; };
struct DeviceStats {
    uint64_t submitted = 0, completed = 0, failed = 0, layers = 0, transferBytes = 0;
    std::vector<Interval> intervals;
};
inline std::vector<Interval> mergeIntervals(std::vector<Interval> v) {
    v.erase(std::remove_if(v.begin(), v.end(), [](const Interval& i) { return i.end <= i.begin; }), v.end());
    std::sort(v.begin(), v.end(), [](const Interval& a, const Interval& b) { return a.begin < b.begin; });
    std::vector<Interval> merged;
    for (const auto& i : v) {
        if (merged.empty() || i.begin > merged.back().end) merged.push_back(i);
        else merged.back().end = std::max(merged.back().end, i.end);
    }
    return merged;
}
inline uint64_t overlapNs(const std::vector<Interval>& a, const std::vector<Interval>& b) {
    const auto x = mergeIntervals(a), y = mergeIntervals(b);
    size_t i = 0, j = 0; uint64_t total = 0;
    while (i < x.size() && j < y.size()) {
        const uint64_t begin = std::max(x[i].begin, y[j].begin);
        const uint64_t end = std::min(x[i].end, y[j].end);
        if (end > begin) total += end - begin;
        if (x[i].end < y[j].end) ++i; else ++j;
    }
    return total;
}
class ExecutionTelemetry {
public:
    bool submitted(uint64_t luid, uint64_t dispatchId) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!luid || !dispatchId || pending_.count(dispatchId)) return false;
        pending_.emplace(dispatchId, luid);
        ++stats_[luid].submitted;
        return true;
    }
    bool complete(uint64_t luid, uint64_t dispatchId, bool success, Interval calibrated = {}) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = pending_.find(dispatchId);
        if (it == pending_.end() || it->second != luid) return false;
        pending_.erase(it);
        auto& s = stats_[luid];
        if (!success) { ++s.failed; return true; }
        ++s.completed;
        if (calibrated.end > calibrated.begin) s.intervals.push_back(calibrated);
        return true;
    }
    void layerCompleted(uint64_t luid) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (luid) ++stats_[luid].layers;
    }
    DeviceStats snapshot(uint64_t luid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stats_.find(luid);
        return it == stats_.end() ? DeviceStats{} : it->second;
    }
private:
    mutable std::mutex mutex_;
    std::unordered_map<uint64_t, uint64_t> pending_;
    std::unordered_map<uint64_t, DeviceStats> stats_;
};
}