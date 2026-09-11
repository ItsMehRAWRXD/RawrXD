#pragma once
/* ScoreboardTypes — GATE=G3_DEEP2_SCOREBOARD_SCHEDULER_LAW_001 ≤99. */
#include <atomic>
#include <cstdint>
#include "ScoreboardInvariants.hpp"

namespace Deep2 {
namespace scoreboard {

using TensorId = uint32_t;
using DeviceId = int32_t;

enum class ResidencyState : uint32_t {
    Absent = 0,
    IoPending = 1,
    RamReady = 2,
    GpuPending = 3,
    GpuReady = 4,
    Executing = 5,
    Retired = 6
};

enum class WorkState : uint8_t {
    Unresolved = 0,
    Needed = 1,
    ReadyExec = 2,
    PeerPending = 3,
    DmaPending = 4,
    IoPending = 5,
    Fault = 6,
    Consumed = 7
};

struct PhysicalWindow {
    uint32_t windowId = 0;
    DeviceId deviceId = -1;
    void* base = nullptr;
    uint64_t capacityBytes = 0;
    std::atomic<uint64_t> allocatedBytes{0};
    std::atomic<uint32_t> locked{0};
};

struct HwToken {
    std::atomic<uint64_t> fence{0};
    std::atomic<uint32_t> done{0};
    void* native = nullptr;
};

struct TensorScore {
    TensorId id = 0;
    uint64_t backingOffset = 0;
    uint64_t backingBytes = 0;
    uint32_t firstUse = 0;
    uint32_t lastUse = 0;
    std::atomic<uint32_t> consumersRemaining{0};
    std::atomic<uint32_t> state{0}; /* ResidencyState */
    PhysicalWindow* ramWindow = nullptr;
    PhysicalWindow* gpuWindow = nullptr;
    HwToken io{};
    HwToken upload{};
    HwToken exec{};
    DeviceId preferredDevice = -1;
    DeviceId currentDevice = -1;
};

struct TensorWork {
    uint32_t tensorId = 0;
    uint32_t firstUse = 0;
    uint32_t nextUse = 0;
    uint32_t lastUse = 0;
    uint32_t dependencyCount = 0;
    uint32_t remainingConsumers = 0;
    uint16_t ramSlot = 0xffffu;
    uint16_t gpuSlot = 0xffffu;
    DeviceId deviceId = -1;
    ResidencyState tier = ResidencyState::Absent;
    WorkState state = WorkState::Unresolved;

    int needed(uint32_t step) const noexcept {
        return state != WorkState::Consumed && firstUse <= step &&
               step <= lastUse;
    }

    int deadAfter(uint32_t step) const noexcept {
        return state != WorkState::ReadyExec && step > lastUse;
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
