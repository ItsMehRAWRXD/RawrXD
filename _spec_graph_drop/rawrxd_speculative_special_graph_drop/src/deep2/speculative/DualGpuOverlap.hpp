#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace rawrxd::deep2::spec {

enum class TransferPath : std::uint8_t {
    SameDevice,
    HostVisibleStaging
};

enum class OverlapOp : std::uint8_t {
    DraftDispatch,
    DraftReadbackTokenIds,
    StageCopyOut,
    StageCopyIn,
    VerifyDispatch,
    AcceptanceDispatch,
    CommitKv
};

struct OverlapStep final {
    OverlapOp op{};
    std::uint8_t device{}; // 0 = target GPU, 1 = draft GPU
    std::uint32_t dependencyMask{};
};

struct DualGpuPlan final {
    TransferPath transfer{TransferPath::HostVisibleStaging};
    std::vector<OverlapStep> steps{};
};

struct DualGpuCapabilities final {
    bool sameDeviceGroup{};
    bool draftDeviceAvailable{};
    bool hostVisibleStaging{};
};

[[nodiscard]] DualGpuPlan buildDualGpuPlan(
    const DualGpuCapabilities& caps);

[[nodiscard]] const char* toString(TransferPath path) noexcept;
[[nodiscard]] const char* toString(OverlapOp op) noexcept;

} // namespace rawrxd::deep2::spec
