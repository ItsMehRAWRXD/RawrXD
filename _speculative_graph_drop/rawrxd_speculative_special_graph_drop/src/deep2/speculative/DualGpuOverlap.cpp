#include "DualGpuOverlap.hpp"

namespace rawrxd::deep2::spec {

DualGpuPlan buildDualGpuPlan(const DualGpuCapabilities& caps) {
    DualGpuPlan plan;

    if (!caps.draftDeviceAvailable) {
        plan.transfer = TransferPath::SameDevice;
        plan.steps = {
            {OverlapOp::DraftDispatch, 0, 0},
            {OverlapOp::VerifyDispatch, 0, 1u << 0},
            {OverlapOp::AcceptanceDispatch, 0, 1u << 1},
            {OverlapOp::CommitKv, 0, 1u << 2}
        };
        return plan;
    }

    if (caps.sameDeviceGroup) {
        plan.transfer = TransferPath::SameDevice;
        plan.steps = {
            {OverlapOp::DraftDispatch, 1, 0},
            {OverlapOp::DraftReadbackTokenIds, 1, 1u << 0},
            {OverlapOp::VerifyDispatch, 0, 1u << 1},
            {OverlapOp::AcceptanceDispatch, 0, 1u << 2},
            {OverlapOp::CommitKv, 0, 1u << 3}
        };
        return plan;
    }

    // Matches RawrXD's already-proven Case B policy:
    // GPU1 -> host-visible staging -> GPU0, with CPU not touching payload.
    plan.transfer = TransferPath::HostVisibleStaging;
    if (!caps.hostVisibleStaging) return plan;

    plan.steps = {
        {OverlapOp::DraftDispatch, 1, 0},
        {OverlapOp::StageCopyOut, 1, 1u << 0},
        {OverlapOp::StageCopyIn, 0, 1u << 1},
        {OverlapOp::VerifyDispatch, 0, 1u << 2},
        {OverlapOp::AcceptanceDispatch, 0, 1u << 3},
        {OverlapOp::CommitKv, 0, 1u << 4}
    };
    return plan;
}

const char* toString(TransferPath path) noexcept {
    switch (path) {
        case TransferPath::SameDevice: return "SameDevice";
        case TransferPath::HostVisibleStaging: return "HostVisibleStaging";
    }
    return "Unknown";
}

const char* toString(OverlapOp op) noexcept {
    switch (op) {
        case OverlapOp::DraftDispatch: return "DraftDispatch";
        case OverlapOp::DraftReadbackTokenIds: return "DraftReadbackTokenIds";
        case OverlapOp::StageCopyOut: return "StageCopyOut";
        case OverlapOp::StageCopyIn: return "StageCopyIn";
        case OverlapOp::VerifyDispatch: return "VerifyDispatch";
        case OverlapOp::AcceptanceDispatch: return "AcceptanceDispatch";
        case OverlapOp::CommitKv: return "CommitKv";
    }
    return "Unknown";
}

} // namespace rawrxd::deep2::spec
