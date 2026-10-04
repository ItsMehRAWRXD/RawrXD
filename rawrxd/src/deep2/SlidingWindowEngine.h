#pragma once
// ============================================================================
// SlidingWindowEngine.h — RAWRXD_DEEP2_SOVEREIGN_SLIDING_WINDOW_001
//
// Real sliding-window context bookkeeping for Deep2 decode.
//
// Contract replaced (measured 2026-10-04):
//   was: struct SlidingWindowConfig { int maxWindow = 512; };
//        class SlidingWindowEngine { int max_window_size = 512;
//                                   std::vector<int> token_buffer; };
//        (a buffer with no eviction, no window math, no accounting)
//
// Realness rules honoured here:
//   - The visible window is COMPUTED from the real sequence length and the
//     real window size. There is no stored "current window" to drift.
//   - evictions / evictionsSuppressed are only incremented when a token is
//     genuinely dropped or genuinely retained, respectively.
//   - A window of 0 is refused at configuration time rather than silently
//     meaning "keep everything".
//
// Window semantics (the standard sliding-window attention rule):
//   a query at absolute position p may attend to positions
//   [max(0, p - window + 1), p]  — i.e. at most `window` positions including
//   itself. This is the arithmetic Deep2Engine::applySlidingWindow() applies
//   to the attention span, and it is the same arithmetic enforced here.
//
// Previously dead: a declared member of Deep2Engine
// (`std::unique_ptr<SlidingWindowEngine> slidingWindow_`), constructed
// nowhere and called nowhere. Now constructed and driven by
// Deep2Engine::enableSlidingWindow() and the per-token decode path.
// ============================================================================
#include <cstddef>
#include <cstdint>
#include <vector>

namespace Deep2 {

struct SlidingWindowConfig {
    int maxWindow = 512;
};

struct SlidingWindowStats {
    std::uint64_t tokensAppended = 0;
    std::uint64_t tokensEvicted = 0;          // dropped from the front
    std::uint64_t evictionsSuppressed = 0;    // would have evicted but head was pinned
    std::uint64_t queriesAnswered = 0;
    std::uint64_t clampedSpans = 0;           // span hit the front of the context
    std::uint64_t resets = 0;
    std::uint64_t refusals = 0;               // configure/push refused
};

class SlidingWindowEngine {
public:
    SlidingWindowEngine() = default;
    explicit SlidingWindowEngine(const SlidingWindowConfig& cfg) { configure(cfg); }

    // A window of <= 0 is refused: it would make every query degenerate.
    bool configure(const SlidingWindowConfig& cfg) {
        if (cfg.maxWindow <= 0) { ++stats_.refusals; return false; }
        config_ = cfg;
        max_window_size = cfg.maxWindow;
        return true;
    }

    bool enabled() const noexcept { return enabled_; }
    void setEnabled(bool on) noexcept { enabled_ = on; }

    int windowSize() const noexcept { return config_.maxWindow; }

    // ---- the real path ---------------------------------------------------
    // Append one decoded token at absolute position `absPos`. Returns false
    // only if the append was refused (window disabled with size 0).
    bool append(int token, std::uint64_t absPos) {
        if (config_.maxWindow <= 0) { ++stats_.refusals; return false; }
        token_buffer.push_back(token);
        positions_.push_back(absPos);
        ++stats_.tokensAppended;
        // A pin requested while the buffer was empty binds to the first token.
        if (pinnedHead_ && !pinnedBound_) { pinnedHeadPos_ = absPos; pinnedBound_ = true; }

        // Evict from the front while the live set is too large. Two conditions
        // can require it, and BOTH are real:
        //   overCount -- more tokens retained than the window allows;
        //   overSpan  -- the absolute positions retained cover more than the
        //                window, which happens when tokens arrive with gaps
        //                (e.g. after a context reset or a sliding jump).
        //
        // The window is a LIMIT. It is never widened to accommodate what was
        // appended: widening here is what silently disables eviction entirely.
        while (positions_.size() > 1) {
            const bool overCount =
                positions_.size() > static_cast<std::size_t>(config_.maxWindow);
            const bool overSpan =
                spanOf(positions_.front(), positions_.back()) >
                    static_cast<std::uint64_t>(config_.maxWindow);
            if (!overCount && !overSpan) break;
            // The pinned head is never dropped. The engine says it declined
            // rather than silently corrupting the retained set.
            if (pinnedHead_ && pinnedBound_ && positions_.front() == pinnedHeadPos_) {
                ++stats_.evictionsSuppressed;
                break;
            }
            token_buffer.erase(token_buffer.begin());
            positions_.erase(positions_.begin());
            ++stats_.tokensEvicted;
        }
        return true;
    }

    // The attention span a query at `absPos` may see, as absolute positions.
    // Returns false when the engine is not configured, leaving the out
    // parameters untouched so the caller cannot act on a fabricated span.
    bool querySpan(std::uint64_t absPos, std::size_t& startOut,
                   std::size_t& endOut) const {
        if (config_.maxWindow <= 0) return false;
        const std::uint64_t w = static_cast<std::uint64_t>(config_.maxWindow);
        const std::size_t start =
            absPos >= (w - 1) ? static_cast<std::size_t>(absPos - (w - 1)) : 0u;
        const std::size_t end = static_cast<std::size_t>(absPos) + 1u;
        startOut = start;
        endOut = end;
        ++stats_.queriesAnswered;
        if (start == 0) ++stats_.clampedSpans;
        return true;
    }

    // Inclusive-exclusive span size for a query at absPos.
    std::size_t spanSizeAt(std::uint64_t absPos) const noexcept {
        if (config_.maxWindow <= 0) return 0;
        const std::uint64_t w = static_cast<std::uint64_t>(config_.maxWindow);
        return static_cast<std::size_t>(absPos < (w - 1) ? absPos + 1 : w);
    }

    std::size_t buffered() const noexcept { return token_buffer.size(); }
    const std::vector<int>& tokens() const noexcept { return token_buffer; }
    std::uint64_t oldestPosition() const noexcept {
        return positions_.empty() ? 0 : positions_.front();
    }
    std::uint64_t newestPosition() const noexcept {
        return positions_.empty() ? 0 : positions_.back();
    }

    // Keep the token at the head from being evicted (used to pin the prompt
    // prefix / system region). Pinning is by ABSOLUTE POSITION, so it survives
    // the buffer sliding. If requested while empty, it binds to the next token.
    void pinHead(bool on) noexcept {
        pinnedHead_ = on;
        pinnedBound_ = false;
        pinnedHeadPos_ = 0;
    }

    void clear() {
        token_buffer.clear();
        positions_.clear();
        pinnedHead_ = false;
        pinnedBound_ = false;
        pinnedHeadPos_ = 0;
        ++stats_.resets;
    }

    const SlidingWindowStats& stats() const noexcept { return stats_; }
    // Fraction of appended tokens that survived, computed from the counters.
    double retention() const noexcept {
        const std::uint64_t appended = stats_.tokensAppended;
        return appended ? static_cast<double>(appended - stats_.tokensEvicted) /
                             static_cast<double>(appended)
                       : 0.0;
    }

private:
    // Number of absolute positions covered, inclusive of both ends.
    static std::uint64_t spanOf(std::uint64_t lo, std::uint64_t hi) noexcept {
        return hi >= lo ? (hi - lo + 1) : 1;
    }

    SlidingWindowConfig config_{};
    // mutable so the const querySpan() can honestly record that it answered a
    // query. Counters stay monotonic; only the storage is mutable.
    mutable SlidingWindowStats stats_{};
    std::vector<int> token_buffer;      // retained name: Deep2Engine.h-era field
    std::vector<std::uint64_t> positions_;
    bool pinnedHead_ = false;
    bool pinnedBound_ = false;
    std::uint64_t pinnedHeadPos_ = 0;
    bool enabled_ = false;
    int max_window_size = 512;
};

} // namespace Deep2
