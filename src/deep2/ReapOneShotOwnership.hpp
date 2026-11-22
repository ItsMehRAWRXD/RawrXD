#pragma once
#include <atomic>
#include <cstdint>
#include <mutex>

namespace Deep2 { namespace Submit {

// Only an actual Vulkan idle result authorizes child-object teardown.
// A timeout, allocation error or other unknown result is NOT device loss.
inline bool MayTeardownAfterIdle(int result) noexcept {
    return result == 0 || result == -4;
}

// One synchronous submission at a time. H56/H57: Acquire/Complete/Drain are
// serialized by an internal mutex so that ticket validation, the active-state
// transition and resource transfer form ONE coherent transaction. A boolean
// CAS alone would be vulnerable to an acquisition ABA race (a new Acquire
// changing epoch_ between ticket validation and the claim). The mutex binds
// acquisition identity, ownership state and resource ownership atomically.
// Active() remains a lock-free read for cheap staging/command rejection.
template<class Handles>
class OneShotOwner {
public:
    bool Active() const noexcept { return active_.load(std::memory_order_acquire); }

    // Returns a per-acquisition ticket (>0) or 0 on failure (already active).
    uint64_t Acquire(const Handles& handles, uint64_t generation) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        // H47-B: admission check and registration share this mutex, so a
        // concurrent SetBlocked(true) (cleanup) cannot interleave between the
        // check and the registration (no check-to-submit TOCTOU).
        if (blocked_.load(std::memory_order_acquire)) return 0;
        if (active_.load(std::memory_order_relaxed)) return 0;
        // H53: ticket overflow -> fail closed (never reuse ticket 0).
        if (nextEpoch_ == UINT64_MAX) return 0;
        handles_ = handles;
        generation_ = generation;
        epoch_ = ++nextEpoch_;   // unique per acquisition (S9.02)
        active_.store(true, std::memory_order_release);
        return epoch_;
    }

    // H47: close/open submission admission atomically with registration.
    // cleanup() calls SetBlocked(true) before destroying resources; initialize()
    // calls SetBlocked(false) after a fresh device is ready.
    void SetBlocked(bool b) noexcept { blocked_.store(b, std::memory_order_release); }
    bool IsBlocked() const noexcept { return blocked_.load(std::memory_order_acquire); }

    // The caller supplies the exact result of the current submission's wait
    // AND the ticket returned by Acquire(). Under the mutex, the ticket check
    // and the ownership transfer are atomic with respect to Acquire (H56/H57).
    template<class Release>
    bool Complete(int result, uint64_t ticket, Release&& release) {
        if (result != 0) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_.load(std::memory_order_relaxed) || ticket != epoch_)
            return false;   // stale/wrong ticket
        release(handles_);
        handles_ = {};
        active_.store(false, std::memory_order_release);
        return true;
    }

    // Teardown of the owning device. Takes the ticket captured BEFORE the idle
    // wait (H38/H39). Under the mutex, validation + transfer are atomic (H56).
    template<class Release>
    bool Drain(int idle, uint64_t ticket, Release&& release) {
        if (!MayTeardownAfterIdle(idle)) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_.load(std::memory_order_relaxed) || ticket != epoch_)
            return false;   // stale ticket -> refuse
        release(handles_);
        handles_ = {};
        active_.store(false, std::memory_order_release);
        return true;
    }

    // The current acquisition's ticket (0 if none). Capture BEFORE a device-idle
    // wait so a subsequent Drain() can detect a new acquisition (H39).
    uint64_t CurrentTicket() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return epoch_;
    }

private:
    mutable std::mutex mutex_;   // serializes Acquire/Complete/Drain (H56/H57)
    Handles  handles_{};
    uint64_t generation_ = 0;
    uint64_t epoch_ = 0;        // current acquisition's ticket
    uint64_t nextEpoch_ = 0;    // monotonic ticket source
    std::atomic<bool> active_{false};
    std::atomic<bool> blocked_{false};   // H47: admission closed during cleanup
};

} } // namespace Deep2::Submit