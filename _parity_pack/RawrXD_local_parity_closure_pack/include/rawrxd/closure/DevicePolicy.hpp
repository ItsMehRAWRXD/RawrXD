#pragma once
#include "Common.hpp"
#include <span>

namespace rawrxd::closure {

enum class DeviceSelector : uint8_t { auto_select, r9700, rx7800xt, dual };

struct DeviceInfo {
    uint32_t ordinal{};
    std::string stable_id;
    std::string name;
    uint64_t local_bytes{};
    uint64_t free_bytes{};
    bool healthy{true};
    bool vulkan{true};
};

struct MeasuredPerformanceProfile {
    std::string model_id;
    std::string device_key;
    double median_tps{};
    double p10_tps{};
    uint32_t samples{};
    bool certified{};
};

struct ModelRequirements {
    std::string model_id;
    uint64_t resident_bytes{};
    uint64_t kv_bytes{};
    uint64_t scratch_bytes{};
};

struct DevicePlan {
    bool ok{};
    std::vector<uint32_t> ordinals;
    std::string device_key;
    std::string reason;
};

class DevicePolicy {
public:
    static std::optional<DeviceSelector> parse(std::string_view);
    static DevicePlan choose(
        DeviceSelector selector,
        const ModelRequirements& model,
        std::span<const DeviceInfo> devices,
        std::span<const MeasuredPerformanceProfile> measured);

private:
    static double score_single(
        const DeviceInfo& d,
        const ModelRequirements& model,
        std::span<const MeasuredPerformanceProfile> measured);
};

} // namespace rawrxd::closure
