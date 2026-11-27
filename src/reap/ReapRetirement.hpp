// ReapRetirement.hpp — RAWRXD S03.7 (completion/cancellation + retirement ledger)
// Tracks pending-retirement bytes (freed only after confirmed completion) and a
// process cancellation flag. Storage-independent; thread-safe; no RNG.
#pragma once
#include <cstdint>
#include <atomic>

namespace RawrXD::Reap {

class RetirementLedger {
public:
    // Register bytes that are pending retirement (not yet safe to free).
    void Retire(uint64_t bytes) noexcept { pending_ += bytes; }
    // Confirm completion of `bytes` (safe to reclaim).
    void Complete(uint64_t bytes) noexcept {
        if (bytes >= pending_) pending_ = 0; else pending_ -= bytes;
    }
    uint64_t Pending() const noexcept { return pending_; }
    // Cancellation (cooperative): set by a Ctrl+C / deadline.
    void Cancel() noexcept { cancel_.store(true); }
    bool Cancelled() const noexcept { return cancel_.load(); }
private:
    std::atomic<uint64_t> pending_{0};
    std::atomic<bool> cancel_{false};
};

} // namespace RawrXD::Reap