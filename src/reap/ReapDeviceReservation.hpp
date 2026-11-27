// ReapDeviceReservation.hpp — RAWRXD S03.6G (reserve-before-allocate + rollback)
// Reserves device capacity BEFORE allocation, commits on success, rolls back on
// failure. Bounded; storage-independent; no RNG. The engine uses this to gate
// Vulkan buffer allocation by the verified transformation identity.
#pragma once
#include <cstdint>

namespace RawrXD::Reap {

class DeviceReservation {
public:
    explicit DeviceReservation(uint64_t budgetBytes) : budget_(budgetBytes) {}
    // Reserve capacity before allocating. False if it would exceed the budget.
    bool Reserve(uint64_t bytes) {
        if (bytes > budget_ - reserved_) return false;
        reserved_ += bytes; return true;
    }
    void Commit(uint64_t bytes) noexcept { if (bytes <= reserved_) reserved_ -= bytes; }   // allocated
    void Rollback(uint64_t bytes) noexcept { if (bytes <= reserved_) reserved_ -= bytes; } // not allocated
    uint64_t Reserved() const noexcept { return reserved_; }
    uint64_t Budget() const noexcept { return budget_; }
private:
    uint64_t budget_, reserved_ = 0;
};

} // namespace RawrXD::Reap