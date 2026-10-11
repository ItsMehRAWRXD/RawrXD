// UTC instrumentation provider - the single authoritative implementation.
//
// ABI (established by the UTC provider audit; the two historical no-op
// variants disagreed on every signature, so neither was restored):
//   UTC_LogEvent(const char* event, const char* detail)  - records an event
//   UTC_ReadCounter(const std::atomic<uint64_t>* counter) - reads a counter
//   g_Counter_Inference : std::atomic<uint64_t>           - inference counter
//
// Real recording, not no-ops: events are kept in a bounded ring with a
// monotonic timestamp, and counters are genuine atomics. Consumers must
// include this header; exactly one implementation is linked.
#pragma once
#include <atomic>
#include <cstdint>

namespace utc {

// Bounded, append-only event log (real recording, fixed footprint).
struct EventRecord {
    uint64_t sequence;
    uint64_t tick;
    const char* event;
    const char* detail;
};

// Appends one event. Returns the assigned sequence number, or 0 if the
// arguments are null. Thread-safe.
uint64_t LogEvent(const char* event, const char* detail);

// Number of events recorded since process start.
uint64_t EventCount();

// Most recent events, newest last. Returns the number copied.
size_t RecentEvents(EventRecord* out, size_t capacity);

// Reads a UTC counter. Returns 0 for a null pointer.
uint64_t ReadCounter(const std::atomic<uint64_t>* counter);

// The inference counter referenced by the license and replay paths.
extern std::atomic<uint64_t> g_Counter_Inference;

}  // namespace utc

// C-compatible surface used by the existing consumers.
inline uint64_t UTC_LogEvent(const char* event, const char* detail)
{
    return utc::LogEvent(event, detail);
}

inline uint64_t UTC_ReadCounter(const std::atomic<uint64_t>* counter)
{
    return utc::ReadCounter(counter);
}
