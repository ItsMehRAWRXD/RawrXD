#pragma once
/* ScoreboardNextRunnable — non-blocking ready-set poll (≠ layer join).
   Prefetch miss on N+2 must not stall independent ready work. LIVE=0. ≤99. */
#include "TensorScoreboard.hpp"

namespace Deep2 {
namespace scoreboard {

enum class RunnableKind : uint32_t {
    None = 0,
    ReadyExec = 1, /* GpuReady → dispatch kernel */
    Upload = 2,    /* RamReady → H2D */
    Io = 3,        /* Absent/IoPending → NVMe range */
    GpuPending = 4,
    Retire = 5
};

struct Runnable {
    TensorId id = 0;
    RunnableKind kind = RunnableKind::None;
};

/* Priority: ReadyExec > Upload > Io > GpuPending > Retire. Never blocks. */
inline int nextRunnable(TensorScoreboard& sb, Runnable& out) {
    TensorId id = 0;
    if (sb.pollReady(id)) {
        out = {id, RunnableKind::ReadyExec};
        return 1;
    }
    if (sb.pollRam(id)) {
        out = {id, RunnableKind::Upload};
        return 1;
    }
    if (sb.pollIo(id)) {
        out = {id, RunnableKind::Io};
        return 1;
    }
    if (sb.pollGpu(id)) {
        out = {id, RunnableKind::GpuPending};
        return 1;
    }
    if (sb.pollRetire(id)) {
        out = {id, RunnableKind::Retire};
        return 1;
    }
    out = {0, RunnableKind::None};
    return 0;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
