#pragma once
// rawrxd_gpu_zipline.hpp — NON-AUTHORITY mobility / placement only.
//
// Authority (never reverse):
//   rawr_uncoherent_object_fabric.hpp  → Acquire → Execute → Publish(g+1)
//   this header                       → where to sit / whether to bounce
//
// Invariant: Execution location may change. Object history may not.
// bounce-house++ may grow (rings, overlap, scoring) but MUST NOT invent,
// repair, or publish generations — fabric alone owns publication.
//
// Lane-local degradation (NOT fail-closed on single peer loss):
//   peer/GPU unavailable → disable that lane → freeze residency → continue
//   stop ONLY when no executable GPU remains (NoExecutableGpu)
// Incomplete mid-flight transfer → discard mobility op; gen unchanged.
//
// HOST_*=0 is a semantic witness: host is immutable weight source only;
// never live-state execution rescue / host-mediated coherence.
// Semantic authority: rawr_uncoherent_object_fabric.hpp
#include "rawr_uncoherent_object_fabric.hpp"
#include <atomic>
#include <cstdint>

namespace rawrxd::zipline {

using u8 = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

inline constexpr const char* kSemanticAuthority =
    "src/deep2/rawr_uncoherent_object_fabric.hpp";
inline constexpr const char* kLaw =
    "Execution location may change; object history may not";
inline constexpr const char* kMobilityLaw =
    "Failed destination disables migration, not execution";

enum class GpuSlot : u8 {
    R9700 = 0,
    RX7800XT = 1,
    Count = 2
};

enum class ZipError : u32 {
    Ok = 0,
    NoExecutableGpu = 1,
    BadArgument = 2
};

struct ZipTelemetry {
    std::atomic<u64> peerSuppress{0};
    std::atomic<u64> gpuSuppress{0};
    std::atomic<u64> offloadCancel{0};
    std::atomic<u64> localContinue{0};
    std::atomic<u64> bounceOk{0};
    std::atomic<u64> mobilityDiscard{0}; // incomplete mid-flight transfer aborted
    std::atomic<u64> r9700Steps{0};
    std::atomic<u64> rx7800xtSteps{0};
    std::atomic<u64> hostComputeCalls{0};
    std::atomic<u64> hostActivationBytes{0};
    std::atomic<u64> hostKvBytes{0};
};

struct GpuLane {
    rawr::fabric::DeviceId id = 0;
    bool ready = false;
    bool peerToOther = false; // live-state peer toward the other slot
};

// Mechanical planner only — does not redefine generation/acquire.
struct ZipPlanner {
    GpuLane lane[2]{};
    ZipTelemetry telem{};

    void set_lane(GpuSlot s, rawr::fabric::DeviceId id, bool ready,
                  bool peerToOther) noexcept {
        auto& L = lane[static_cast<u32>(s)];
        L.id = id;
        L.ready = ready;
        L.peerToOther = peerToOther;
    }

    bool gpu_ready(GpuSlot s) const noexcept {
        return lane[static_cast<u32>(s)].ready;
    }

    bool peer_ready(GpuSlot from, GpuSlot to) const noexcept {
        if (from == to) return true;
        return lane[static_cast<u32>(from)].ready &&
               lane[static_cast<u32>(to)].ready &&
               lane[static_cast<u32>(from)].peerToOther;
    }

    // Choose next residency: bounce if peer OK, else freeze on current.
    ZipError choose_next(GpuSlot current, GpuSlot desired,
                         GpuSlot& out) noexcept {
        out = current;

        if (!gpu_ready(current)) {
            telem.gpuSuppress.fetch_add(1, std::memory_order_relaxed);
            // Fall over to other if ready.
            const GpuSlot other =
                (current == GpuSlot::R9700) ? GpuSlot::RX7800XT : GpuSlot::R9700;
            if (gpu_ready(other)) {
                out = other;
                telem.localContinue.fetch_add(1, std::memory_order_relaxed);
                return ZipError::Ok;
            }
            return ZipError::NoExecutableGpu;
        }

        if (desired == current) {
            telem.localContinue.fetch_add(1, std::memory_order_relaxed);
            return ZipError::Ok;
        }

        if (!gpu_ready(desired)) {
            telem.gpuSuppress.fetch_add(1, std::memory_order_relaxed);
            telem.offloadCancel.fetch_add(1, std::memory_order_relaxed);
            telem.localContinue.fetch_add(1, std::memory_order_relaxed);
            out = current;
            return ZipError::Ok;
        }

        if (!peer_ready(current, desired)) {
            telem.peerSuppress.fetch_add(1, std::memory_order_relaxed);
            telem.offloadCancel.fetch_add(1, std::memory_order_relaxed);
            telem.localContinue.fetch_add(1, std::memory_order_relaxed);
            out = current; // freeze — no host-stage
            return ZipError::Ok;
        }

        out = desired;
        telem.bounceOk.fetch_add(1, std::memory_order_relaxed);
        return ZipError::Ok;
    }

    // Mid-flight peer death: discard incomplete mobility; residency stays current.
    // Does NOT touch fabric generations — caller must not publish from this alone.
    ZipError abort_mid_flight(GpuSlot current, GpuSlot& out) noexcept {
        telem.mobilityDiscard.fetch_add(1, std::memory_order_relaxed);
        telem.offloadCancel.fetch_add(1, std::memory_order_relaxed);
        telem.peerSuppress.fetch_add(1, std::memory_order_relaxed);
        telem.localContinue.fetch_add(1, std::memory_order_relaxed);
        out = current;
        return ZipError::Ok;
    }

    void note_step(GpuSlot s) noexcept {
        if (s == GpuSlot::R9700)
            telem.r9700Steps.fetch_add(1, std::memory_order_relaxed);
        else
            telem.rx7800xtSteps.fetch_add(1, std::memory_order_relaxed);
    }

    bool host_clean() const noexcept {
        return telem.hostComputeCalls.load() == 0 &&
               telem.hostActivationBytes.load() == 0 &&
               telem.hostKvBytes.load() == 0;
    }
};

} // namespace rawrxd::zipline
