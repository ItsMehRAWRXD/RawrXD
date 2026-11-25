// ============================================================================
// ReservationLedger.hpp — DEEP2_ATOMIC_RESERVATION_001
//
// Authoritative atomic per-key (per-LUID) reservation accounting for the VRAM
// allocator.  Prevents concurrent model admissions from overcommitting a device
// that is already fully or partially reserved by other in-flight loads.
//
// Semantics:
//   * capacity is per key (LUID, or deviceIndex when LUID is unknown)
//   * a key is UNKNOWN until SetCapacity() is called; a strict reserve on an
//     unknown key is rejected unless allowUnknown is set (fail-closed)
//   * a KNOWN capacity of 0 rejects every reserve (fully allocated)
//   * TryReserveMulti is transactional: either all holds apply or none do
//   * Release(id) rolls back / frees a reservation (RAII uses this)
//   * all operations are atomic under one mutex; reserved never exceeds a known
//     capacity (no oversubscription), which the contention test asserts
//
// Header-only, no dependencies beyond the standard library.
// ============================================================================
#ifndef RAWRXD_DEEP2_RESERVATION_LEDGER_HPP
#define RAWRXD_DEEP2_RESERVATION_LEDGER_HPP

#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Deep2 {
namespace MultiGPU {

using ReserveHold = std::pair<uint64_t, uint64_t>; // (key, bytes)

struct Reservation {
    uint64_t id = 0;
    bool valid = false;
    std::vector<ReserveHold> holds;
};

class ReservationLedger {
public:
    // Declare a known capacity for a key (idempotent; lowers/raises the cap).
    void SetCapacity(uint64_t key, uint64_t bytes) {
        std::lock_guard<std::mutex> lk(mu_);
        Slot& s = slots_[key];
        s.cap = bytes;
        s.known = true;
    }

    // Mark a key's capacity as unknown (strict reserves will be rejected).
    void SetUnknown(uint64_t key) {
        std::lock_guard<std::mutex> lk(mu_);
        Slot& s = slots_[key];
        s.known = false;
        s.cap = 0;
    }

    bool Known(uint64_t key) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = slots_.find(key);
        return it != slots_.end() && it->second.known;
    }

    uint64_t Capacity(uint64_t key) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = slots_.find(key);
        return it == slots_.end() ? 0 : it->second.cap;
    }

    uint64_t Reserved(uint64_t key) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = slots_.find(key);
        return it == slots_.end() ? 0 : it->second.reserved;
    }

    // Single-key reserve.  Returns false (no state change) on any failure.
    bool TryReserve(uint64_t key, uint64_t bytes, bool allowUnknown,
                    Reservation& out) {
        return TryReserveMulti({{key, bytes}}, allowUnknown, out);
    }

    // Transactional multi-key reserve.  On any failure, no hold is applied.
    bool TryReserveMulti(const std::vector<ReserveHold>& reqs,
                         bool allowUnknown,
                         Reservation& out) {
        out = Reservation{};
        if (reqs.empty()) return false;

        std::lock_guard<std::mutex> lk(mu_);

        // Phase 1: validate every hold against current state (no mutation).
        for (const auto& r : reqs) {
            auto it = slots_.find(r.first);
            const bool known = it != slots_.end() && it->second.known;
            const uint64_t cap = known ? it->second.cap : 0;
            const uint64_t used = it != slots_.end() ? it->second.reserved : 0;
            if (!known) {
                if (!allowUnknown) return false;      // strict: reject unknown
            } else {
                if (r.second > cap || used > cap - r.second)
                    return false;                     // would oversubscribe
            }
        }

        // Phase 2: apply all holds atomically.
        const uint64_t id = nextId_++;
        for (const auto& r : reqs) {
            Slot& s = slots_[r.first];
            s.reserved += r.second;
            if (!s.known) { s.known = true; s.cap = r.second; } // adopt unknown
            holds_[id].push_back(r);
        }
        out.id = id;
        out.valid = true;
        out.holds = reqs;
        return true;
    }

    // Release/rollback a reservation by id.  Returns false if id is unknown.
    bool Release(uint64_t id) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = holds_.find(id);
        if (it == holds_.end()) return false;
        for (const auto& r : it->second) {
            auto s = slots_.find(r.first);
            if (s != slots_.end()) {
                s->second.reserved = (r.second > s->second.reserved)
                                         ? 0
                                         : s->second.reserved - r.second;
            }
        }
        holds_.erase(it);
        return true;
    }

private:
    struct Slot {
        uint64_t cap = 0;
        uint64_t reserved = 0;
        bool known = false;
    };

    mutable std::mutex mu_;
    std::unordered_map<uint64_t, Slot> slots_;
    std::unordered_map<uint64_t, std::vector<ReserveHold>> holds_;
    uint64_t nextId_ = 1;
};

// RAII owner: reserves on construction, releases on destruction unless released.
class ScopedReservation {
public:
    ScopedReservation(ReservationLedger& ledger,
                      const std::vector<ReserveHold>& reqs,
                      bool allowUnknown)
        : ledger_(&ledger) {
        owns_ = ledger_->TryReserveMulti(reqs, allowUnknown, res_);
    }
    ~ScopedReservation() {
        if (owns_) ledger_->Release(res_.id);
    }
    ScopedReservation(const ScopedReservation&) = delete;
    ScopedReservation& operator=(const ScopedReservation&) = delete;

    bool valid() const { return owns_ && res_.valid; }
    uint64_t id() const { return res_.id; }

    void release() {
        if (owns_) { ledger_->Release(res_.id); owns_ = false; }
    }

private:
    ReservationLedger* ledger_;
    Reservation res_;
    bool owns_ = false;
};

} // namespace MultiGPU
} // namespace Deep2

#endif // RAWRXD_DEEP2_RESERVATION_LEDGER_HPP