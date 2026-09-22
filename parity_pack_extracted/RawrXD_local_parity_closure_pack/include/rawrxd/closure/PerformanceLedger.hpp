#pragma once
#include "DevicePolicy.hpp"
#include <filesystem>

namespace rawrxd::closure {

struct PerformanceSample {
    std::string model_id;
    std::string device_key;
    uint64_t model_fingerprint{};
    uint32_t prompt_tokens{};
    uint32_t generated_tokens{};
    uint64_t elapsed_us{};
    bool strict{};
    bool passed{};
};

class PerformanceLedger {
public:
    explicit PerformanceLedger(std::filesystem::path path) : path_(std::move(path)) {}

    bool append(const PerformanceSample& sample, std::string* error = nullptr) const;
    std::vector<PerformanceSample> load(std::string* error = nullptr) const;
    std::vector<MeasuredPerformanceProfile> summarize(uint32_t min_cert_samples = 3) const;

private:
    std::filesystem::path path_;
};

} // namespace rawrxd::closure
