// ============================================================================
// MixedPrecisionPipeline.hpp - FP16/BF16/FP8 Mixed Precision Pipeline
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

struct MixedPrecisionConfig {
    bool enableFP16 = true;
    bool enableBF16 = true;
    bool enableFP8 = false;
    bool enableAutocast = true;
    float lossScale = 1.0f;
    uint32_t castFrequency = 1;
};

class MixedPrecisionPipeline {
public:
    MixedPrecisionPipeline();
    ~MixedPrecisionPipeline();

    bool Initialize(const MixedPrecisionConfig& config);
    void Shutdown();

    void* CastToFP16(const float* input, size_t count);
    void* CastToBF16(const float* input, size_t count);
    void* CastToFP8(const float* input, size_t count);
    void CastBackToFP32(const void* input, float* output, size_t count, int srcType);

    bool Autocast(std::vector<float>& data, int& currentType);
    void UpdateLossScale(float scale);

    struct PipelineStats {
        uint64_t totalCasts;
        uint64_t fp16Casts;
        uint64_t bf16Casts;
        uint64_t fp8Casts;
        uint64_t overflowEvents;
    };
    PipelineStats GetStats() const { return stats_; }

private:
    MixedPrecisionConfig config_;
    PipelineStats stats_;
    bool initialized_ = false;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
