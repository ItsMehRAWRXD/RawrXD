// K2RainbowFoldTable.hpp
// Native Deep2 runtime rainbow fold bank.
// Header-only (C++20), fixed storage, no JSON, no heap table, no extra TU/CMake entry.
//
// Semantics:
//   ROUTING      = may steer the next physical execution choice.
//   NON_ROUTING  = evidence remains live/visible, but cannot steer.
//   FROZEN       = generic policy cannot flip route state.
//   MUTABLE      = may be promoted/demoted by a later critical-owner witness.
//   COMPLETED    = known-good completed path/result.
//   CANDIDATE    = next ROO candidate.
//   LOST         = measured losing route, banked so it is not rediscovered.
//   FALLBACK     = known completing recovery route.
//
// Important:
//   "non-routing" does NOT mean "do not execute".
//   It means "do not let this component-time witness choose the route."
//
// Operator (reverse-bound):
//   )ter*N  ≡  N*ret(   — route-result folded backward into non-routing authority N.
//   ≠ N ∘ route. Split work allowed; authority plane never moves.
//   *dlof = inspect/reconstruct only (emit); never mutates the bank.
//
// _006 intended state:
//   SPLIT_KV       ROUTING     FROZEN   COMPLETED
//   Q_BRANCH       ROUTING     FROZEN   COMPLETED
//   KV_A_BRANCH    NON_ROUTING FROZEN   COMPLETED
//   Q_A_KERNEL     ROUTING     MUTABLE  CANDIDATE
//   Q_B_KERNEL     NON_ROUTING MUTABLE  CANDIDATE
//   LOGITS         NON_ROUTING MUTABLE  COMPLETED

#pragma once
#include <array>
#include <cstdint>
#include <cstdio>
#include <mutex>

namespace Deep2 {

enum class RainbowRoute : uint8_t {
    NON_ROUTING = 0,
    ROUTING = 1,
};

enum class RainbowFreeze : uint8_t {
    MUTABLE = 0,
    FROZEN = 1,
};

enum class RainbowFoldState : uint8_t {
    EMPTY = 0,
    CANDIDATE = 1,
    COMPLETED = 2,
    LOST = 3,
    FALLBACK = 4,
};

enum class RainbowFoldId : uint8_t {
    QKV_SPLIT_KV = 0,
    QKV_SERIAL_REUSE,
    Q_BRANCH,
    KV_A_BRANCH,
    Q_A_KERNEL,
    Q_B_KERNEL,
    MLA_O_PROJ,
    MLA_KV_EXPAND_HOST,
    MLA_KV_EXPAND_GPU_DUAL,
    LOGITS,
    SHARD_IO,
    COUNT
};

struct RainbowFoldEntry {
    RainbowRoute route = RainbowRoute::NON_ROUTING;
    RainbowFreeze freeze = RainbowFreeze::MUTABLE;
    RainbowFoldState state = RainbowFoldState::EMPTY;
    uint64_t witnessUs = 0;
    uint64_t epoch = 0;
    uint64_t completed = 0;
    uint64_t lost = 0;
};

struct RainbowCriticalWitness {
    bool splitKvLive = false;
    bool parityOk = true;
    bool maxBucketMla = false;
    bool qkvStageCritical = false;
    bool qBranchCritical = false;
    bool qaCritical = false;
    bool qbCritical = false;
    uint64_t qkvWallUs = 0;
    uint64_t qBranchUs = 0;
    uint64_t kvBranchUs = 0;
    uint64_t qaKernelUs = 0;
    uint64_t qbKernelUs = 0;
    uint64_t oProjUs = 0;
    uint64_t kvExpandUs = 0;
    uint64_t logitsUs = 0;
};

namespace RainbowFoldDetail {
inline std::mutex g_mu;
inline std::array<RainbowFoldEntry,
                  static_cast<size_t>(RainbowFoldId::COUNT)>
    g_fold{};
inline uint64_t g_epoch = 0;

inline constexpr size_t Idx(RainbowFoldId id) noexcept {
    return static_cast<size_t>(id);
}

inline const char* IdName(RainbowFoldId id) noexcept {
    switch (id) {
    case RainbowFoldId::QKV_SPLIT_KV: return "QKV_SPLIT_KV";
    case RainbowFoldId::QKV_SERIAL_REUSE: return "QKV_SERIAL_REUSE";
    case RainbowFoldId::Q_BRANCH: return "Q_BRANCH";
    case RainbowFoldId::KV_A_BRANCH: return "KV_A_BRANCH";
    case RainbowFoldId::Q_A_KERNEL: return "Q_A_KERNEL";
    case RainbowFoldId::Q_B_KERNEL: return "Q_B_KERNEL";
    case RainbowFoldId::MLA_O_PROJ: return "MLA_O_PROJ";
    case RainbowFoldId::MLA_KV_EXPAND_HOST: return "MLA_KV_EXPAND_HOST";
    case RainbowFoldId::MLA_KV_EXPAND_GPU_DUAL: return "MLA_KV_EXPAND_GPU_DUAL";
    case RainbowFoldId::LOGITS: return "LOGITS";
    case RainbowFoldId::SHARD_IO: return "SHARD_IO";
    default: return "UNKNOWN";
    }
}

inline const char* RouteName(RainbowRoute v) noexcept {
    return v == RainbowRoute::ROUTING ? "ROUTING" : "NON_ROUTING";
}
inline const char* FreezeName(RainbowFreeze v) noexcept {
    return v == RainbowFreeze::FROZEN ? "FROZEN" : "MUTABLE";
}
inline const char* StateName(RainbowFoldState v) noexcept {
    switch (v) {
    case RainbowFoldState::CANDIDATE: return "CANDIDATE";
    case RainbowFoldState::COMPLETED: return "COMPLETED";
    case RainbowFoldState::LOST: return "LOST";
    case RainbowFoldState::FALLBACK: return "FALLBACK";
    default: return "EMPTY";
    }
}

inline void SetLocked(RainbowFoldId id, RainbowRoute route,
                      RainbowFreeze freeze, RainbowFoldState state,
                      uint64_t witnessUs) noexcept {
    auto& e = g_fold[Idx(id)];
    e.route = route;
    e.freeze = freeze;
    e.state = state;
    e.witnessUs = witnessUs;
    e.epoch = ++g_epoch;
    if (state == RainbowFoldState::COMPLETED) ++e.completed;
    if (state == RainbowFoldState::LOST) ++e.lost;
}

inline bool MayMutateLocked(RainbowFoldId id) noexcept {
    return g_fold[Idx(id)].freeze != RainbowFreeze::FROZEN;
}
} // namespace RainbowFoldDetail

inline void K2RainbowFold_ResetAll() noexcept {
    using namespace RainbowFoldDetail;
    std::lock_guard<std::mutex> lock(g_mu);
    g_fold = {};
    g_epoch = 0;
}

inline void K2RainbowFold_SetMeasured(RainbowFoldId id, RainbowRoute route,
                                      RainbowFreeze freeze,
                                      RainbowFoldState state,
                                      uint64_t witnessUs = 0) noexcept {
    using namespace RainbowFoldDetail;
    std::lock_guard<std::mutex> lock(g_mu);
    SetLocked(id, route, freeze, state, witnessUs);
}

inline bool K2RainbowFold_TrySetRoute(RainbowFoldId id,
                                      RainbowRoute route) noexcept {
    using namespace RainbowFoldDetail;
    std::lock_guard<std::mutex> lock(g_mu);
    if (!MayMutateLocked(id)) return false;
    auto& e = g_fold[Idx(id)];
    e.route = route;
    e.epoch = ++g_epoch;
    return true;
}

inline void K2RainbowFold_Freeze(RainbowFoldId id) noexcept {
    using namespace RainbowFoldDetail;
    std::lock_guard<std::mutex> lock(g_mu);
    auto& e = g_fold[Idx(id)];
    e.freeze = RainbowFreeze::FROZEN;
    e.epoch = ++g_epoch;
}

inline void K2RainbowFold_Thaw(RainbowFoldId id) noexcept {
    using namespace RainbowFoldDetail;
    std::lock_guard<std::mutex> lock(g_mu);
    auto& e = g_fold[Idx(id)];
    e.freeze = RainbowFreeze::MUTABLE;
    e.epoch = ++g_epoch;
}

inline RainbowFoldEntry K2RainbowFold_Get(RainbowFoldId id) noexcept {
    using namespace RainbowFoldDetail;
    std::lock_guard<std::mutex> lock(g_mu);
    return g_fold[Idx(id)];
}

inline bool K2RainbowFold_IsFrozenRouting(RainbowFoldId id) noexcept {
    const auto e = K2RainbowFold_Get(id);
    return e.route == RainbowRoute::ROUTING &&
           e.freeze == RainbowFreeze::FROZEN &&
           (e.state == RainbowFoldState::COMPLETED ||
            e.state == RainbowFoldState::FALLBACK);
}

inline void K2RainbowFold_BankLost(RainbowFoldId id, uint64_t witnessUs = 0,
                                   bool freeze = true) noexcept {
    K2RainbowFold_SetMeasured(
        id, RainbowRoute::NON_ROUTING,
        freeze ? RainbowFreeze::FROZEN : RainbowFreeze::MUTABLE,
        RainbowFoldState::LOST, witnessUs);
}

inline void K2RainbowFold_ParityFallback() noexcept {
    using namespace RainbowFoldDetail;
    std::lock_guard<std::mutex> lock(g_mu);
    SetLocked(RainbowFoldId::QKV_SPLIT_KV, RainbowRoute::NON_ROUTING,
              RainbowFreeze::MUTABLE, RainbowFoldState::LOST,
              g_fold[Idx(RainbowFoldId::QKV_SPLIT_KV)].witnessUs);
    SetLocked(RainbowFoldId::QKV_SERIAL_REUSE, RainbowRoute::ROUTING,
              RainbowFreeze::FROZEN, RainbowFoldState::FALLBACK,
              g_fold[Idx(RainbowFoldId::QKV_SERIAL_REUSE)].witnessUs);
}

inline void K2RainbowFold_ObserveCritical(
    const RainbowCriticalWitness& w) noexcept {
    using namespace RainbowFoldDetail;
    std::lock_guard<std::mutex> lock(g_mu);

    if (!w.parityOk) {
        SetLocked(RainbowFoldId::QKV_SPLIT_KV, RainbowRoute::NON_ROUTING,
                  RainbowFreeze::MUTABLE, RainbowFoldState::LOST, w.qkvWallUs);
        SetLocked(RainbowFoldId::QKV_SERIAL_REUSE, RainbowRoute::ROUTING,
                  RainbowFreeze::FROZEN, RainbowFoldState::FALLBACK, 0);
        return;
    }

    if (w.splitKvLive) {
        SetLocked(RainbowFoldId::QKV_SPLIT_KV, RainbowRoute::ROUTING,
                  RainbowFreeze::FROZEN, RainbowFoldState::COMPLETED,
                  w.qkvWallUs);
        SetLocked(RainbowFoldId::QKV_SERIAL_REUSE, RainbowRoute::NON_ROUTING,
                  RainbowFreeze::FROZEN, RainbowFoldState::FALLBACK, 0);
    }

    if (w.maxBucketMla && w.qkvStageCritical && w.qBranchCritical) {
        SetLocked(RainbowFoldId::Q_BRANCH, RainbowRoute::ROUTING,
                  RainbowFreeze::FROZEN, RainbowFoldState::COMPLETED,
                  w.qBranchUs);
        SetLocked(RainbowFoldId::KV_A_BRANCH, RainbowRoute::NON_ROUTING,
                  RainbowFreeze::FROZEN, RainbowFoldState::COMPLETED,
                  w.kvBranchUs);

        if (w.qaCritical) {
            SetLocked(RainbowFoldId::Q_A_KERNEL, RainbowRoute::ROUTING,
                      RainbowFreeze::MUTABLE, RainbowFoldState::CANDIDATE,
                      w.qaKernelUs);
            SetLocked(RainbowFoldId::Q_B_KERNEL, RainbowRoute::NON_ROUTING,
                      RainbowFreeze::MUTABLE, RainbowFoldState::CANDIDATE,
                      w.qbKernelUs);
        } else if (w.qbCritical) {
            SetLocked(RainbowFoldId::Q_A_KERNEL, RainbowRoute::NON_ROUTING,
                      RainbowFreeze::MUTABLE, RainbowFoldState::CANDIDATE,
                      w.qaKernelUs);
            SetLocked(RainbowFoldId::Q_B_KERNEL, RainbowRoute::ROUTING,
                      RainbowFreeze::MUTABLE, RainbowFoldState::CANDIDATE,
                      w.qbKernelUs);
        }

        SetLocked(RainbowFoldId::MLA_O_PROJ, RainbowRoute::NON_ROUTING,
                  RainbowFreeze::MUTABLE, RainbowFoldState::CANDIDATE,
                  w.oProjUs);
        SetLocked(RainbowFoldId::MLA_KV_EXPAND_HOST, RainbowRoute::NON_ROUTING,
                  RainbowFreeze::FROZEN, RainbowFoldState::COMPLETED,
                  w.kvExpandUs);
        SetLocked(RainbowFoldId::LOGITS, RainbowRoute::NON_ROUTING,
                  RainbowFreeze::MUTABLE, RainbowFoldState::COMPLETED,
                  w.logitsUs);
    }
}

inline void K2RainbowFold_CriticalOwnerChanged(
    RainbowFoldId oldOwner, RainbowFoldId newOwner,
    uint64_t newWitnessUs = 0) noexcept {
    using namespace RainbowFoldDetail;
    std::lock_guard<std::mutex> lock(g_mu);
    auto& oldE = g_fold[Idx(oldOwner)];
    oldE.freeze = RainbowFreeze::MUTABLE;
    oldE.route = RainbowRoute::NON_ROUTING;
    oldE.epoch = ++g_epoch;
    auto& newE = g_fold[Idx(newOwner)];
    newE.route = RainbowRoute::ROUTING;
    newE.freeze = RainbowFreeze::MUTABLE;
    if (newE.state == RainbowFoldState::EMPTY)
        newE.state = RainbowFoldState::CANDIDATE;
    newE.witnessUs = newWitnessUs;
    newE.epoch = ++g_epoch;
}

inline void K2RainbowFold_Emit(FILE* f) noexcept {
    using namespace RainbowFoldDetail;
    if (!f) return;
    std::lock_guard<std::mutex> lock(g_mu);
    std::fprintf(f, "OPERATOR=)ter*N\nOPERATOR_FWD=N*ret(\nAUTHORITY=MLA_Gemv\n");
    for (size_t i = 0; i < g_fold.size(); ++i) {
        const auto id = static_cast<RainbowFoldId>(i);
        const auto& e = g_fold[i];
        if (e.state == RainbowFoldState::EMPTY) continue;
        std::fprintf(
            f,
            "K2_RAINBOW_FOLD ID=%s ROUTE=%s FREEZE=%s STATE=%s "
            "US=%llu EPOCH=%llu COMPLETED=%llu LOST=%llu\n",
            IdName(id), RouteName(e.route), FreezeName(e.freeze),
            StateName(e.state),
            static_cast<unsigned long long>(e.witnessUs),
            static_cast<unsigned long long>(e.epoch),
            static_cast<unsigned long long>(e.completed),
            static_cast<unsigned long long>(e.lost));
    }
    std::fflush(f);
}

} // namespace Deep2
