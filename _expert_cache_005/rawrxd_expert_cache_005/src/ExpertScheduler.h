#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace rawrxd {

struct ExpertDeviceState {
    uint32_t deviceId{};
    uint64_t budgetBytes{};
    uint64_t residentBytes{};
    uint64_t inflightBytes{};
    uint64_t recentComputeUs{};
    uint64_t recentTransferUs{};
    bool available{true};
};

struct ExpertPlacementRequest {
    uint32_t layer{};
    uint32_t expert{};
    uint64_t bytes{};
    float routerProbability{};
    int32_t currentDevice{-1};
};

struct ExpertPlacementDecision {
    int32_t device{-1};
    bool migrate{false};
    double score{};
};

class ExpertScheduler {
public:
    ExpertPlacementDecision choose(const ExpertPlacementRequest& req,
                                   const std::vector<ExpertDeviceState>& devices) const noexcept;
private:
    static double score(const ExpertPlacementRequest&, const ExpertDeviceState&) noexcept;
};

struct SchedulerTelemetry {
    uint64_t decisions{};
    uint64_t migrations{};
    uint64_t rejectedNoCapacity{};
    uint64_t cpuExpertCompute{}; // must remain 0
};

} // namespace rawrxd
