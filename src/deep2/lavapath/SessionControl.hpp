#pragma once
/* Session cancel authority — control plane only. ZERO Vulkan. ≤99. */
#include <atomic>
#include <cstdint>

namespace rawr::product_run {

struct SessionControl {
    std::atomic<bool> cancelRequested{false};

    void RequestCancel() noexcept {
        cancelRequested.store(true, std::memory_order_release);
    }
    void Clear() noexcept {
        cancelRequested.store(false, std::memory_order_release);
    }
    bool IsCancelled() const noexcept {
        return cancelRequested.load(std::memory_order_acquire);
    }
};

inline void RequestCancel(SessionControl& s) noexcept { s.RequestCancel(); }

inline bool IsCancelled(const SessionControl& s) noexcept { return s.IsCancelled(); }

enum class StopReason : uint8_t {
    None = 0,
    Eog,
    MaxTokens,
    Cancelled,
    Error
};

} // namespace rawr::product_run
