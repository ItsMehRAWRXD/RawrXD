// ResidencyReplay.hpp — deterministic predictive residency planning
//
// This is deliberately a CPU-only planning and replay layer.  It can rank
// expert candidates and replay routing traces without claiming that a Vulkan
// transfer occurred.  The production streamer remains the authority for
// admission, allocation epochs, and GPU completion.
#pragma once

#include "VulkanWeightStreamer.hpp"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace Deep2 {

struct ResidencyCandidate {
    WeightTensorId tensor = 0;
    uint64_t bytes = 0;
    double probability = 0.0;
    double reloadCost = 0.0;
    double expectedReuse = 0.0;
    uint64_t deadlineStep = 0;
    uint32_t priority = 0;
};

struct PlannedResidency {
    ResidencyCandidate candidate{};
    double score = 0.0;
    bool admitted = false;
};

class ExpertResidencyPlanner {
public:
    explicit ExpertResidencyPlanner(uint64_t byteBudget = 0,
                                    uint64_t lookahead = 8) noexcept
        : byteBudget_(byteBudget), lookahead_(lookahead) {}

    void setBudget(uint64_t bytes) noexcept { byteBudget_ = bytes; }
    uint64_t budget() const noexcept { return byteBudget_; }
    uint64_t lookahead() const noexcept { return lookahead_; }

    std::vector<PlannedResidency> plan(
        const std::vector<ResidencyCandidate>& candidates,
        uint64_t currentStep) const {
        std::vector<PlannedResidency> ranked;
        ranked.reserve(candidates.size());
        for (const auto& c : candidates) {
            if (!c.tensor || !c.bytes || !std::isfinite(c.probability) ||
                !std::isfinite(c.reloadCost) || !std::isfinite(c.expectedReuse) ||
                c.probability <= 0.0 || c.reloadCost < 0.0 ||
                c.expectedReuse < 0.0)
                continue;
            if (c.deadlineStep > currentStep + lookahead_) continue;
            const double score =
                (c.probability * c.reloadCost * c.expectedReuse) /
                static_cast<double>(c.bytes);
            ranked.push_back({c, score, false});
        }
        std::stable_sort(ranked.begin(), ranked.end(),
                         [](const PlannedResidency& a,
                            const PlannedResidency& b) {
                             if (a.score != b.score) return a.score > b.score;
                             if (a.candidate.priority != b.candidate.priority)
                                 return a.candidate.priority > b.candidate.priority;
                             return a.candidate.tensor < b.candidate.tensor;
                         });
        uint64_t used = 0;
        for (auto& item : ranked) {
            if (item.candidate.bytes <= byteBudget_ - (used <= byteBudget_ ? used : byteBudget_)) {
                item.admitted = true;
                used += item.candidate.bytes;
            }
        }
        return ranked;
    }

private:
    uint64_t byteBudget_ = 0;
    uint64_t lookahead_ = 8;
};

enum class ResidencyTraceKind : uint8_t {
    PrefetchIssued,
    CacheHit,
    Ready,
    DispatchAcquire,
    DispatchRelease,
    Evicted,
    Failed
};

struct ResidencyTraceEvent {
    uint64_t step = 0;
    WeightTensorId tensor = 0;
    uint64_t bytes = 0;
    uint64_t allocationEpoch = 0;
    ResidencyTraceKind kind = ResidencyTraceKind::Failed;
};

class ResidencyTraceRecorder {
public:
    void record(ResidencyTraceEvent event) { events_.push_back(event); }
    const std::vector<ResidencyTraceEvent>& events() const noexcept { return events_; }
    void clear() noexcept { events_.clear(); }

    void emit(FILE* f) const {
        if (!f) f = stdout;
        std::fprintf(f, "RESIDENCY_TRACE_EVENTS=%zu\n", events_.size());
        for (const auto& e : events_) {
            std::fprintf(f, "RESIDENCY_TRACE step=%llu tensor=%llu bytes=%llu epoch=%llu kind=%u\n",
                         static_cast<unsigned long long>(e.step),
                         static_cast<unsigned long long>(e.tensor),
                         static_cast<unsigned long long>(e.bytes),
                         static_cast<unsigned long long>(e.allocationEpoch),
                         static_cast<unsigned>(e.kind));
        }
        std::fflush(f);
    }

private:
    std::vector<ResidencyTraceEvent> events_;
};

struct ResidencyReplayRequest {
    WeightTensorId tensor = 0;
    uint64_t bytes = 0;
};

struct ResidencyReplayResult {
    uint64_t requests = 0;
    uint64_t transfers = 0;
    uint64_t cacheHits = 0;
    uint64_t evictions = 0;
    uint64_t rejected = 0;
    uint64_t bytesTransferred = 0;
    std::string status = "NOT_RUN";
};

// Replays a routing sequence with an LRU cache.  This intentionally models
// transfer admission only; it does not model GPU execution or timing.
class ResidencyReplaySimulator {
public:
    explicit ResidencyReplaySimulator(uint64_t capacityBytes) noexcept
        : capacityBytes_(capacityBytes) {}

    ResidencyReplayResult run(const std::vector<ResidencyReplayRequest>& sequence,
                              ResidencyTraceRecorder* trace = nullptr) const {
        ResidencyReplayResult result{};
        if (sequence.empty()) return result;
        std::unordered_map<WeightTensorId, Entry> resident;
        std::vector<WeightTensorId> lru;
        uint64_t used = 0;
        uint64_t epoch = 0;
        for (size_t i = 0; i < sequence.size(); ++i) {
            const auto& request = sequence[i];
            ++result.requests;
            if (!request.tensor || !request.bytes || request.bytes > capacityBytes_) {
                ++result.rejected;
                if (trace) trace->record({static_cast<uint64_t>(i), request.tensor,
                                          request.bytes, 0,
                                          ResidencyTraceKind::Failed});
                continue;
            }
            const auto hit = resident.find(request.tensor);
            if (hit != resident.end()) {
                ++result.cacheHits;
                touch(lru, request.tensor);
                if (trace) trace->record({static_cast<uint64_t>(i), request.tensor,
                                          request.bytes, hit->second.epoch,
                                          ResidencyTraceKind::CacheHit});
                continue;
            }
            while (used + request.bytes > capacityBytes_ && !lru.empty()) {
                const WeightTensorId victim = lru.front();
                lru.erase(lru.begin());
                const auto victimIt = resident.find(victim);
                if (victimIt == resident.end()) continue;
                used -= victimIt->second.bytes;
                if (trace) trace->record({static_cast<uint64_t>(i), victim,
                                          victimIt->second.bytes, victimIt->second.epoch,
                                          ResidencyTraceKind::Evicted});
                resident.erase(victimIt);
                ++result.evictions;
            }
            if (used + request.bytes > capacityBytes_) {
                ++result.rejected;
                if (trace) trace->record({static_cast<uint64_t>(i), request.tensor,
                                          request.bytes, 0,
                                          ResidencyTraceKind::Failed});
                continue;
            }
            const uint64_t allocationEpoch = ++epoch;
            resident.emplace(request.tensor, Entry{request.bytes, allocationEpoch});
            lru.push_back(request.tensor);
            used += request.bytes;
            ++result.transfers;
            result.bytesTransferred += request.bytes;
            if (trace) {
                trace->record({static_cast<uint64_t>(i), request.tensor, request.bytes,
                               allocationEpoch, ResidencyTraceKind::PrefetchIssued});
                trace->record({static_cast<uint64_t>(i), request.tensor, request.bytes,
                               allocationEpoch, ResidencyTraceKind::Ready});
            }
        }
        result.status = result.rejected ? "FAIL" :
                        (result.transfers ? "PASS" : "NOT_RUN");
        return result;
    }

private:
    struct Entry { uint64_t bytes = 0; uint64_t epoch = 0; };
    static void touch(std::vector<WeightTensorId>& lru, WeightTensorId tensor) {
        const auto it = std::find(lru.begin(), lru.end(), tensor);
        if (it != lru.end()) lru.erase(it);
        lru.push_back(tensor);
    }
    uint64_t capacityBytes_ = 0;
};

} // namespace Deep2
