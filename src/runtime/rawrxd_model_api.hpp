#pragma once
#include <string>
#include <vector>

namespace RawrXD {
    class InternalModelInstance;

    struct InternalGenerationConfig {
        float temperature;
        float top_p;
        uint32_t max_tokens;
    };

    class RawrXDModelEngine {
    public:
        RawrXDModelEngine();
        ~RawrXDModelEngine();
        bool Initialize(const std::string& filepath);
        std::string ExecuteInference(const std::string& prompt, const InternalGenerationConfig& cfg);
        void HotpatchLayerWeights(uint32_t layer_id, const std::vector<float>& patched_weights);
        void RevertLayerWeights(uint32_t layer_id);
    private:
        InternalModelInstance* impl;
    };
} // namespace RawrXD
