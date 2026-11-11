#pragma once
// Native C++ UTC event stream. Intentionally namespaced: the historical MASM
// ABI exports C symbols UTC_LogEvent(const char*) and UTC_ReadCounter(QWORD*).
// It must not be silently replaced by a different C++ function signature.
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace utc {
constexpr std::size_t kRingCapacity = 256;
constexpr std::size_t kEventBytes = 80;
constexpr std::size_t kDetailBytes = 192;

struct EventRecord {
    std::uint64_t sequence = 0;
    std::uint64_t tick = 0;
    std::array<char, kEventBytes> event{};
    std::array<char, kDetailBytes> detail{};
};

// Single-process bounded event recorder. Owns the strings; callers can safely
// supply stack buffers. All writes and readbacks are serialized by one mutex.
std::uint64_t LogEvent(const char* event, const char* detail) noexcept;
std::uint64_t EventCount() noexcept;
std::size_t RecentEvents(EventRecord* out, std::size_t capacity) noexcept;

std::uint64_t ReadCounter(const std::atomic<std::uint64_t>* counter) noexcept;
extern std::atomic<std::uint64_t> g_Counter_Inference;
} // namespace utc
