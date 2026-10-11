// UTC instrumentation provider - implementation.
#include "utc_provider.h"

#include <atomic>
#include <cstdint>

namespace utc {

namespace {

constexpr size_t kRingCapacity = 256;

struct Ring {
    std::atomic<uint64_t> sequence{0};
    std::atomic<uint64_t> next{0};
    EventRecord slots[kRingCapacity];
};

Ring& ring()
{
    static Ring r;
    return r;
}

// Monotonic tick source (real time, not a compile-time constant).
uint64_t NowTick()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

}  // namespace

std::atomic<uint64_t> g_Counter_Inference{0};

uint64_t LogEvent(const char* event, const char* detail)
{
    if (!event) return 0;
    Ring& r = ring();
    const uint64_t seq = r.sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    const uint64_t idx = r.next.fetch_add(1, std::memory_order_relaxed) % kRingCapacity;
    r.slots[idx].sequence = seq;
    r.slots[idx].tick = NowTick();
    r.slots[idx].event = event;
    r.slots[idx].detail = detail;
    return seq;
}

uint64_t EventCount()
{
    return ring().sequence.load(std::memory_order_relaxed);
}

size_t RecentEvents(EventRecord* out, size_t capacity)
{
    if (!out || capacity == 0) return 0;
    Ring& r = ring();
    const uint64_t total = r.sequence.load(std::memory_order_relaxed);
    const uint64_t available = total < static_cast<uint64_t>(kRingCapacity)
                                   ? total
                                   : static_cast<uint64_t>(kRingCapacity);
    const uint64_t n = available < capacity ? available : capacity;
    for (uint64_t i = 0; i < n; ++i) {
        // Newest last: walk backwards from the write cursor.
        const uint64_t back = n - 1 - i;
        const uint64_t idx =
            (r.next.load(std::memory_order_relaxed) + kRingCapacity - 1 - back) %
            kRingCapacity;
        out[i] = r.slots[idx];
    }
    return static_cast<size_t>(n);
}

uint64_t ReadCounter(const std::atomic<uint64_t>* counter)
{
    return counter ? counter->load(std::memory_order_relaxed) : 0;
}

}  // namespace utc
