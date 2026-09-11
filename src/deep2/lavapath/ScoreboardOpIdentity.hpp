#pragma once
/* ScoreboardOpIdentity — ReadyExec payload fields. P3 SOURCE. ≤99. */
#include "ScoreboardTypes.hpp"

namespace Deep2 {
namespace scoreboard {

enum class OpKind : uint8_t {
    None = 0,
    ForwardLayer = 1,
    Mla = 2,
    Gemv = 3,
    HostDecode = 4
};

struct ExecOpIdentity {
    TensorId tensorId = 0;
    uint32_t layer = 0;
    OpKind op = OpKind::None;
    DeviceId device = -1;
    uint32_t leaseId = 0xffffffffu;
    uint64_t generation = 0;
    uint16_t ramSlot = 0xffffu;
    uint16_t gpuSlot = 0xffffu;
};

inline void FillOpFromScore(const TensorScore& t, ExecOpIdentity& o) noexcept {
    o.tensorId = t.id;
    o.layer = t.firstUse; /* BindProductOpen: id==layer tip */
    o.op = OpKind::ForwardLayer;
    o.device = t.currentDevice >= 0 ? t.currentDevice : t.preferredDevice;
    o.leaseId = t.gpuWindow ? t.gpuWindow->windowId : 0xffffffffu;
    o.generation = t.exec.fence.load(std::memory_order_acquire);
    o.ramSlot = t.ramWindow ? (uint16_t)t.ramWindow->windowId : 0xffffu;
    o.gpuSlot = t.gpuWindow ? (uint16_t)t.gpuWindow->windowId : 0xffffu;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
