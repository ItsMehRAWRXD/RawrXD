#pragma once
/* AsyncSubmission — timeline completion → scoreboard edge. LIVE=0. ≤99. */
#include "ScoreboardTypes.hpp"
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

enum class SyncOp : uint32_t {
    IoToRam = 0,
    RamToGpu = 1,
    GpuKernel = 2,
    PeerXfer = 3
};

struct AsyncSubmission {
    TensorId tensorId = 0;
    uint64_t timelineValue = 0;
    SyncOp op = SyncOp::RamToGpu;
    ResidencyState from = ResidencyState::Absent;
    ResidencyState to = ResidencyState::Absent;
    uint32_t decrementConsumer = 0;
    HwToken* token = nullptr;
};

struct TimelineSignal {
    uint64_t value = 0;
    void* semaphore = nullptr; /* VkSemaphore opaque */
};

} /* namespace scoreboard */
} /* namespace Deep2 */
