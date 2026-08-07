// ============================================================================
// Blocker #17: MARS Eviction Thrashing Fix
// Prevents thrashing at 80% VRAM threshold by:
// - Adding hysteresis to eviction decisions
// - Batch evicting multiple tensors at once
// - Prioritizing eviction of least-recently-used tensors
// ============================================================================
#pragma once
#include <cstdint>
#include <vector>
#include <queue>
#include <functional>
#include <chrono>
#include <unordered_map>
#include <mutex>
#include <algorithm>

namespace Deep2 {
namespace MARS {

struct EvictionCandidate {
    uint64_t tensorId;
    float priority;
    uint64_t lastAccessTime;
    size_t bytes;
    int gpu;
    
    // Higher score = more likely to be evicted
    float GetEvictionScore(uint64_t currentTime) const {
        uint64_t age = currentTime - lastAccessTime;
        float ageFactor = static_cast<float>(age) / 1000.0f; // ms
        return ageFactor / (priority + 0.1f); // Lower priority = higher score
    }
};

class EvictionThrashingFix {
public:
    EvictionThrashingFix()
        : highThreshold_(0.80f)
        , lowThreshold_(0.65f)
        , currentState_(State::NORMAL)
        , lastEvictionTime_(0)
        , minEvictionIntervalMs_(50)
        , batchEvictionCount_(4)
    {}

    void SetThresholds(float high, float low) {
        highThreshold_ = high;
        lowThreshold_ = low;
    }

    void SetMinEvictionInterval(uint32_t ms) { minEvictionIntervalMs_ = ms; }
    void SetBatchSize(size_t n) { batchEvictionCount_ = n; }

    // Check if eviction should be triggered based on current VRAM usage
    bool ShouldEvict(float vramRatio) {
        auto now = GetTickCount64();
        
        // Enforce minimum interval between evictions
        if (now - lastEvictionTime_ < minEvictionIntervalMs_) {
            return false;
        }
        
        switch (currentState_) {
            case State::NORMAL:
                if (vramRatio >= highThreshold_) {
                    currentState_ = State::EVICTING;
                    return true;
                }
                return false;
                
            case State::EVICTING:
                if (vramRatio <= lowThreshold_) {
                    currentState_ = State::NORMAL;
                    return false;
                }
                // Still above low threshold - continue evicting if above high
                if (vramRatio >= highThreshold_) {
                    return true;
                }
                // Between low and high - hysteresis prevents flip-flopping
                return false;
                
            case State::CRITICAL:
                // Critical state - evict aggressively
                if (vramRatio <= lowThreshold_) {
                    currentState_ = State::NORMAL;
                } else if (vramRatio < highThreshold_) {
                    currentState_ = State::EVICTING;
                }
                return vramRatio > lowThreshold_;
        }
        return false;
    }

    // Select candidates for eviction using LRU + priority scoring
    std::vector<uint64_t> SelectEvictionCandidates(
        const std::vector<EvictionCandidate>& candidates,
        size_t targetBytes) {
        
        std::vector<EvictionCandidate> sorted = candidates;
        auto now = GetTickCount64();
        
        // Sort by eviction score (highest first)
        std::sort(sorted.begin(), sorted.end(),
            [now](const EvictionCandidate& a, const EvictionCandidate& b) {
                return a.GetEvictionScore(now) > b.GetEvictionScore(now);
            });
        
        std::vector<uint64_t> result;
        size_t selectedBytes = 0;
        
        for (const auto& cand : sorted) {
            if (result.size() >= batchEvictionCount_ && selectedBytes >= targetBytes) {
                break;
            }
            result.push_back(cand.tensorId);
            selectedBytes += cand.bytes;
        }
        
        lastEvictionTime_ = now;
        return result;
    }

    // Mark state as critical (e.g., after allocation failure)
    void SetCritical() { currentState_ = State::CRITICAL; }

    // Get current state
    enum class State { NORMAL, EVICTING, CRITICAL };
    State GetState() const { return currentState_; }

    // Get time since last eviction in ms
    uint64_t GetTimeSinceLastEviction() const {
        return GetTickCount64() - lastEvictionTime_;
    }

private:
    float highThreshold_;
    float lowThreshold_;
    State currentState_;
    uint64_t lastEvictionTime_;
    uint32_t minEvictionIntervalMs_;
    size_t batchEvictionCount_;
};

} // namespace MARS
} // namespace Deep2
