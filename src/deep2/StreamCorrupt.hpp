#pragma once
/* Permanent inference corruption — no retry / no fallback once set. */
#include <atomic>
#include <cstdint>

namespace Deep2 {

struct StreamCorruptState {
    std::atomic<int> flag{0};
    std::atomic<const char*> stage{"NONE"};
    std::atomic<const char*> owner{"NONE"};
};

inline StreamCorruptState& StreamCorrupt_S() {
    static StreamCorruptState s;
    return s;
}

inline void StreamCorrupt_Clear() noexcept {
    auto& s = StreamCorrupt_S();
    s.flag.store(0, std::memory_order_release);
    s.stage.store("NONE", std::memory_order_relaxed);
    s.owner.store("NONE", std::memory_order_relaxed);
}

/* First writer wins; stage/owner are static string literals only. */
inline void StreamCorrupt_Note(const char* stage, const char* owner) noexcept {
    auto& s = StreamCorrupt_S();
    int expected = 0;
    if (s.flag.compare_exchange_strong(expected, 1, std::memory_order_acq_rel)) {
        if (stage) s.stage.store(stage, std::memory_order_relaxed);
        if (owner) s.owner.store(owner, std::memory_order_relaxed);
    }
}

inline bool StreamCorrupt() noexcept {
    return StreamCorrupt_S().flag.load(std::memory_order_acquire) != 0;
}

inline const char* StreamCorrupt_Stage() noexcept {
    const char* p = StreamCorrupt_S().stage.load(std::memory_order_relaxed);
    return p ? p : "NONE";
}

inline const char* StreamCorrupt_Owner() noexcept {
    const char* p = StreamCorrupt_S().owner.load(std::memory_order_relaxed);
    return p ? p : "NONE";
}

} // namespace Deep2
