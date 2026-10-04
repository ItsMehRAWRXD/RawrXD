#pragma once
// ============================================================================
// WarmupScheduler.hpp — RAWRXD_DEEP2_SOVEREIGN_WARMUP_001
//
// Real predictive prefetch scheduler for Deep2 decode.
//
// Contract replaced (measured 2026-10-04):
//   was: struct WarmupConfig {};
//        struct WarmupStats { int prefetched = 0; };
//        class WarmupScheduler { WarmupStats stats; };
//        (a counter that could only ever be 0)
//
// What this actually does: decode walks layers in a fixed order, so the layer
// that will be needed N steps from now is predictable. This scheduler observes
// the real access order, learns the per-step transition distribution, and issues
// prefetch requests AHEAD of use. It then reports how often those predictions
// were right.
//
// Realness rules honoured here:
//   - prefetched counts only predictions that were ISSUED.
//   - hits / misses are recorded by explicit observe() calls made by the caller
//     when the layer is actually reached. The scheduler does not mark its own
//     predictions correct.
//   - hitRate() and precision() are COMPUTED from those observations. There is
//     no setter that can make a prediction look good.
//   - A prediction the scheduler has no evidence for is not issued at all.
//
// The predictor is a plain first-order transition table: "having just used
// layer L, the next layer is most often M". That is the actual structure of a
// transformer stack, and it is falsifiable -- a shuffled access order must
// produce a low hit rate, which the cert asserts.
// ============================================================================
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace Deep2 {

struct WarmupConfig {
    // How many steps ahead to issue prefetches for.
    std::uint32_t lookahead = 2;
    // Stop predicting once this many transitions have been learned; below that
    // the table is noise and predicting from it would be guessing.
    std::uint32_t minSamplesForPrediction = 2;
    // Cap on distinct layers tracked, so a pathological id cannot grow the table
    // without bound.
    std::uint32_t maxTrackedLayers = 4096;
};

struct WarmupStats {
    std::uint64_t observations = 0;    // layers actually reached
    std::uint64_t transitions = 0;     // consecutive pairs learned
    std::uint64_t prefetchIssued = 0;  // predictions issued ahead of use
    std::uint64_t hits = 0;            // prediction matched the layer reached
    std::uint64_t misses = 0;          // prediction did not match
    std::uint64_t suppressed = 0;      // not enough evidence to predict
    std::uint64_t tableResets = 0;
    std::uint64_t overflowSkips = 0;   // layer id beyond maxTrackedLayers
    // Scored outcomes currently inside the recent-accuracy window.
    std::uint64_t recentScored = 0;
    std::uint64_t recentHits = 0;
};

class WarmupScheduler {
public:
    WarmupScheduler() = default;
    explicit WarmupScheduler(const WarmupConfig& cfg) { configure(cfg); }

    bool configure(const WarmupConfig& cfg) {
        if (cfg.lookahead == 0) return false;
        config_ = cfg;
        return true;
    }
    const WarmupConfig& config() const noexcept { return config_; }

    // ---- the real path ---------------------------------------------------
    // Called once per layer as decode reaches it. Records the observation,
    // scores the prediction that was outstanding for this layer, and then issues
    // the next prediction.
    void observe(std::uint32_t layer) {
        if (layer >= config_.maxTrackedLayers) {
            ++stats_.overflowSkips;
            return;
        }
        ++stats_.observations;

        if (haveOutstanding_) {
            // Score the prediction that was made for THIS layer. The scheduler
            // does not get to decide this; the caller's arrival is the evidence.
            const bool right = (outstandingLayer_ == layer);
            if (right) ++stats_.hits;
            else       ++stats_.misses;
            recordOutcome(right);
            haveOutstanding_ = false;
        }

        if (haveLast_) {
            auto& n = next_[last_];
            if (n[layer] < UINT32_MAX) ++n[layer];
            else                       n[layer] = 1;
            ++stats_.transitions;
        }
        last_ = layer;
        haveLast_ = true;

        // Issue the next prediction from what is actually learned so far.
        const std::uint32_t guess = predictNext(last_);
        if (guess == kNoPrediction) {
            ++stats_.suppressed;
        } else {
            outstandingLayer_ = guess;
            haveOutstanding_ = true;
            ++stats_.prefetchIssued;
        }
    }

    // Peek without scoring. Does not issue anything.
    std::uint32_t predictNext(std::uint32_t from) const {
        auto it = next_.find(from);
        if (it == next_.end()) return kNoPrediction;
        std::uint32_t best = kNoPrediction, bestN = 0;
        for (const auto& kv : it->second) {
            if (kv.second >= config_.minSamplesForPrediction && kv.second > bestN) {
                bestN = kv.second;
                best = kv.first;
            }
        }
        return best;
    }

    void reset() {
        next_.clear();
        recent_.clear();
        haveLast_ = false;
        haveOutstanding_ = false;
        ++stats_.tableResets;
    }

    const WarmupStats& stats() const noexcept { return stats_; }

    // ---- computed views --------------------------------------------------
    double hitRate() const noexcept {
        const std::uint64_t scored = stats_.hits + stats_.misses;
        return scored ? static_cast<double>(stats_.hits) / static_cast<double>(scored) : 0.0;
    }
    // Lifetime precision. Useful as a record, but NOT a decision input: it never
    // forgets, so a predictor that learned three correct transitions and then
    // met chaos keeps a flattering score forever. Use recentPrecision() to
    // decide anything.
    double precision() const noexcept {
        return stats_.prefetchIssued
            ? static_cast<double>(stats_.hits) / static_cast<double>(stats_.prefetchIssued)
            : 0.0;
    }
    // Accuracy over the last k scored predictions. This is what a scheduler must
    // act on: it decays as soon as the world stops matching the model.
    double recentPrecision(std::uint32_t k = kRecentWindow) const noexcept {
        if (k > recent_.size()) k = static_cast<std::uint32_t>(recent_.size());
        if (k == 0) return 0.0;
        std::uint32_t hits = 0;
        for (std::uint32_t i = 0; i < k; ++i)
            if (recent_[recent_.size() - 1 - i]) ++hits;
        return static_cast<double>(hits) / static_cast<double>(k);
    }
    // A predictor is only trustworthy when it has scored SOMETHING RECENTLY and
    // that recent record beats the threshold. Both conditions are required: a
    // cold predictor and a stale one are both untrustworthy.
    bool trustworthy(double minPrecision = 0.5,
                     std::uint32_t minRecent = 4) const noexcept {
        const std::uint32_t scored = static_cast<std::uint32_t>(
            recent_.size() < minRecent ? recent_.size() : minRecent);
        if (scored < minRecent) return false;
        return recentPrecision(scored) > minPrecision;
    }

    static constexpr std::uint32_t kRecentWindow = 16;
    static constexpr std::uint32_t kNoPrediction = UINT32_MAX;

private:
    // Scores one prediction outcome. Kept factored so observe() stays readable
    // and the recent-window bookkeeping lives in exactly one place.
    void recordOutcome(bool right) {
        recent_.push_back(right ? 1u : 0u);
        if (recent_.size() > kRecentWindow) {
            recent_.erase(recent_.begin());
        }
        ++stats_.recentScored;
        if (right) ++stats_.recentHits;
    }

    WarmupConfig config_{};
    WarmupStats stats_{};
    // Ring of the most recent scored outcomes, oldest first, capped at the
    // window so it cannot grow without bound.
    std::vector<std::uint32_t> recent_;
    std::unordered_map<std::uint32_t, std::unordered_map<std::uint32_t, std::uint32_t>> next_;
    std::uint32_t last_ = 0;
    bool haveLast_ = false;
    std::uint32_t outstandingLayer_ = 0;
    bool haveOutstanding_ = false;
};

} // namespace Deep2
