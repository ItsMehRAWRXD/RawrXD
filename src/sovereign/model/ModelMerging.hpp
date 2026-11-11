// ============================================================================
// ModelMerging.hpp - Model Merging (SLERP, TIES, DARE)
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

enum class MergeMethod { SLERP, TIES, DARE, LINEAR, TASK_ARITHMETIC };

struct MergeConfig {
    MergeMethod method = MergeMethod::SLERP;
    std::vector<float> weights;
    float mergeRatio = 0.5f;
    float density = 0.5f; // for DARE
    uint32_t maxRetries = 3;
    std::string outputPath;
};

class ModelMerging {
public:
    ModelMerging();
    ~ModelMerging();

    bool Merge(const std::vector<std::string>& modelPaths, const MergeConfig& config);
    bool SLERP(const std::vector<float>& a, const std::vector<float>& b, std::vector<float>& out, float t);
    bool TIES(const std::vector<std::vector<float>>& tensors, std::vector<float>& out, float density);
    bool DARE(const std::vector<float>& a, const std::vector<float>& b, std::vector<float>& out, float density, float scale);
    bool Linear(const std::vector<float>& a, const std::vector<float>& b, std::vector<float>& out, float t);

    struct MergeStats { uint64_t totalMerges; uint64_t totalTensors; uint64_t totalParams; };
    MergeStats GetStats() const { return stats_; }

private:
    MergeStats stats_;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
