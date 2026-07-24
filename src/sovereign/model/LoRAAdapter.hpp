// ============================================================================
// LoRAAdapter.hpp - LoRA/QLoRA Adapter Inference
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

struct LoRAConfig {
    uint64_t r = 16;
    float alpha = 16.0f;
    float dropout = 0.0f;
    std::string targetModules;
    bool useQuantized = false;
    int quantBits = 4;
};

struct LoRAWeight {
    std::string name;
    std::vector<float> loraA;
    std::vector<float> loraB;
    uint64_t inDim;
    uint64_t outDim;
    uint64_t r;
    float alpha;
};

class LoRAAdapter {
public:
    LoRAAdapter();
    ~LoRAAdapter();

    bool Load(const std::string& path);
    bool LoadFromGGUF(const std::string& ggufPath);
    void Unload();

    bool Apply(const std::string& layerName, const float* input, float* output, uint64_t dim);
    bool ApplyToAll(std::vector<float>& hiddenStates, uint64_t dim);

    void SetScale(float scale) { scale_ = scale; }
    float GetScale() const { return scale_; }
    bool IsLoaded() const { return !weights_.empty(); }
    size_t GetWeightCount() const { return weights_.size(); }

private:
    std::vector<LoRAWeight> weights_;
    float scale_ = 1.0f;
    mutable std::mutex mutex_;
};

class QLoRAAdapter : public LoRAAdapter {
public:
    bool LoadQuantized(const std::string& path, int bits = 4);
    bool ApplyDequantized(const std::string& layerName, const float* input, float* output, uint64_t dim);
};

} // namespace Sovereign
