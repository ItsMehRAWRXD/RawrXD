#pragma once
/* TimelineDispatch — bind + pending table + poll→scoreboard. LIVE=0. ≤99. */
#include "AsyncSubmission.hpp"
#include "TensorScoreboard.hpp"
#include "TimelineSemaphoreFns.hpp"
#include <atomic>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct TimelineDispatch {
    static constexpr uint32_t kPend = 128;
    TensorScoreboard* sb = nullptr;
    TimelineSemaphoreFns fn{};
    VkSem timeline = nullptr;
    std::atomic<uint64_t> nextVal{1};
    AsyncSubmission pend[kPend]{};
    std::atomic<uint32_t> live[kPend]{};

    int bind(TensorScoreboard* s, const TimelineSemaphoreFns& f) {
        if (!s || !f.device || !f.createTimeline || !f.getCounter || !f.queueSubmit)
            return 0;
        sb = s;
        fn = f;
        if (fn.createTimeline(fn.device, 0, &timeline, fn.ud) != 0 || !timeline)
            return 0;
        for (uint32_t i = 0; i < kPend; ++i)
            live[i].store(0, std::memory_order_relaxed);
        return 1;
    }

    int track(const AsyncSubmission& sub) {
        for (uint32_t i = 0; i < kPend; ++i) {
            uint32_t e = 0;
            if (!live[i].compare_exchange_strong(e, 1, std::memory_order_acq_rel,
                                                 std::memory_order_relaxed))
                continue;
            pend[i] = sub;
            return 1;
        }
        return 0;
    }

    int poll(uint32_t maxApply) {
        if (!sb || !fn.getCounter)
            return 0;
        uint64_t cur = 0;
        if (fn.getCounter(fn.device, timeline, &cur, fn.ud) != 0)
            return 0;
        uint32_t applied = 0;
        for (uint32_t i = 0; i < kPend && applied < maxApply; ++i) {
            if (!live[i].load(std::memory_order_acquire))
                continue;
            AsyncSubmission& s = pend[i];
            if (s.timelineValue > cur)
                continue;
            if (s.token)
                s.token->done.store(1, std::memory_order_release);
            if (s.decrementConsumer)
                (void)sb->onConsumerDone(s.tensorId);
            else
                (void)sb->transition(s.tensorId, s.from, s.to);
            live[i].store(0, std::memory_order_release);
            ++applied;
        }
        return (int)applied;
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
