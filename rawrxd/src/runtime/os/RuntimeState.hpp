// ============================================================================
// RuntimeState.hpp — Global runtime state (health, counters, mode)
// ============================================================================
#pragma once
#include <atomic>
#include <string>
#include <chrono>

namespace rawrxd::runtime {

enum class RuntimeMode : uint8_t {
    Boot = 0,
    Running,
    Suspended,
    ShuttingDown,
    Shutdown
};

struct RuntimeState {
    std::atomic<RuntimeMode> mode{RuntimeMode::Boot};
    std::atomic<uint64_t> bootTimeNs{0};
    std::atomic<uint64_t> capabilitiesAdmitted{0};
    std::atomic<uint64_t> capabilitiesFailed{0};
    std::atomic<uint64_t> executionCount{0};
    std::atomic<uint64_t> verificationCount{0};
    std::atomic<uint64_t> receiptCount{0};
    std::atomic<bool> healthy{false};

    void recordBoot() {
        bootTimeNs.store(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count(),
            std::memory_order_release);
    }

    uint64_t uptimeNs() const {
        auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        return now - bootTimeNs.load(std::memory_order_acquire);
    }
};

} // namespace rawrxd::runtime