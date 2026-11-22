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
template<class Handles>
class OneShotOwner {
public:
    bool Active() const noexcept { return active_.load(std::memory_order_acquire); }
    bool Acquire(const Handles& handles, uint64_t generation) noexcept {
        if (Active()) return false;
        handles_ = handles;
        generation_ = generation;
        active_.store(true, std::memory_order_release);
        return true;
    }
    // The caller supplies the exact result of the current submission's wait.
    template<class Release>
    bool Complete(int result, uint64_t generation, Release&& release) {
        if (result != 0) return false;
        return ReleaseCurrent(generation, release);
    }
    // Teardown of the owning device, not an ordinary reuse boundary.
    template<class Release>
    bool Drain(int idle, uint64_t generation, Release&& release) {
        if (!MayTeardownAfterIdle(idle)) return false;
        return ReleaseCurrent(generation, release);
    }
private:
    template<class Release>
    bool ReleaseCurrent(uint64_t generation, Release& release) {
        if (!Active() || generation != generation_) return false;
        release(handles_);
        handles_ = {};
        active_.store(false, std::memory_order_release);
        return true;
    }
    Handles handles_{};
    uint64_t generation_ = 0;
    std::atomic<bool> active_{false};
};

} } // namespace Deep2::Submit
