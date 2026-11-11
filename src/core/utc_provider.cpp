#include "utc_provider.h"
#include <chrono>
#include <algorithm>
#include <cstdio>
#include <mutex>

namespace utc {
namespace {
struct Ring {
    std::mutex lock;
    std::uint64_t count = 0;
    std::array<EventRecord, kRingCapacity> slots{};
};

Ring& ring() noexcept {
    static Ring instance;
    return instance;
}

std::uint64_t steady_tick() noexcept {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(duration_cast<nanoseconds>(
        steady_clock::now().time_since_epoch()).count());
}

template <std::size_t N>
void copy_text(std::array<char, N>& out, const char* value) noexcept {
    std::snprintf(out.data(), out.size(), "%s", value ? value : "");
}
} // namespace

std::atomic<std::uint64_t> g_Counter_Inference{0};

std::uint64_t LogEvent(const char* event, const char* detail) noexcept {
    if (!event) return 0;
    auto& r = ring();
    std::lock_guard<std::mutex> guard(r.lock);
    const auto sequence = ++r.count;
    auto& slot = r.slots[(sequence - 1) % kRingCapacity];
    slot.sequence = sequence;
    slot.tick = steady_tick();
    copy_text(slot.event, event);
    copy_text(slot.detail, detail);
    return sequence;
}

std::uint64_t EventCount() noexcept {
    auto& r = ring();
    std::lock_guard<std::mutex> guard(r.lock);
    return r.count;
}

std::size_t RecentEvents(EventRecord* out, std::size_t capacity) noexcept {
    if (!out || !capacity) return 0;
    auto& r = ring();
    std::lock_guard<std::mutex> guard(r.lock);
    const auto n = static_cast<std::size_t>(
        std::min<std::uint64_t>(r.count, std::min(capacity, kRingCapacity)));
    const auto first = r.count - n + 1;
    for (std::size_t i = 0; i < n; ++i) {
        const auto sequence = first + i;
        out[i] = r.slots[(sequence - 1) % kRingCapacity];
    }
    return n;
}

std::uint64_t ReadCounter(const std::atomic<std::uint64_t>* counter) noexcept {
    return counter ? counter->load(std::memory_order_relaxed) : 0;
}
} // namespace utc
