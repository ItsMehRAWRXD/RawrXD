#pragma once
#include <atomic>
#include <cstdint>

namespace Deep2 { namespace Submit {

// Only an actual Vulkan idle result authorizes child-object teardown.
// A timeout, allocation error or other unknown result is NOT device loss.
inline bool MayTeardownAfterIdle(int result) noexcept {
    return result == 0 || result == -4;
}

// One synchronous submission at a time. Writers are serialized by the
// production API mutex; cleanup requires quiesced callers. The atomic flag
// permits cheap rejection by staging/command acquisition paths. No heap
// allocation is necessary on the post-submit failure path.
//
// S9.02: Acquire() returns a per-acquisition TICKET (epoch), not just a bool.
// Complete() requires the matching ticket, so a stale completion from a
// previous acquisition — even within the SAME reused device generation —
// cannot release the current submission's resources. Generation equality
// alone is insufficient; the ticket binds completion to the exact acquisition.
template<class Handles>
class OneShotOwner {
public:
    bool Active() const noexcept { return active_.load(std::memory_order_acquire); }

    // Returns a per-acquisition ticket (>0) or 0 on failure (already active).
    uint64_t Acquire(const Handles& handles, uint64_t generation) noexcept {
        if (Active()) return 0;
        handles_ = handles;
        generation_ = generation;
        epoch_ = ++nextEpoch_;   // unique per acquisition (S9.02)
        active_.store(true, std::memory_order_release);
        return epoch_;
    }

    // The caller supplies the exact result of the current submission's wait
    // AND the ticket returned by Acquire(). A stale ticket is rejected.
    template<class Release>
    bool Complete(int result, uint64_t ticket, Release&& release) {
        if (result != 0) return false;
        if (!Active() || ticket != epoch_) return false;   // stale/wrong ticket
        release(handles_);
        handles_ = {};
        active_.store(false, std::memory_order_release);
        return true;
    }

    // Teardown of the owning device, not an ordinary reuse boundary. Takes the
    // ticket captured BEFORE the idle wait (H38/H39): if a new acquisition
    // occurred after idle evidence was collected, the stale ticket no longer
    // matches epoch_ and the drain is refused — a new submission is never
    // reclaimed with stale idle evidence.
    template<class Release>
    bool Drain(int idle, uint64_t ticket, Release&& release) {
        if (!MayTeardownAfterIdle(idle)) return false;
        if (!Active() || ticket != epoch_) return false;   // stale ticket -> refuse
        release(handles_);
        handles_ = {};
        active_.store(false, std::memory_order_release);
        return true;
    }

    // The current acquisition's ticket (0 if none). Capture BEFORE a device-idle
    // wait so a subsequent Drain() can detect a new acquisition (H39).
    uint64_t CurrentTicket() const noexcept { return epoch_; }

private:
    Handles  handles_{};
    uint64_t generation_ = 0;
    uint64_t epoch_ = 0;        // current acquisition's ticket
    uint64_t nextEpoch_ = 0;    // monotonic ticket source
    std::atomic<bool> active_{false};
};

} } // namespace Deep2::Submit