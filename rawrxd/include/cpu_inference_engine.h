// Stub header: cpu_inference_engine.h
// Minimal declarations to satisfy #include references.
#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace RawrXD {

class CPUInferenceEngine {
public:
    struct Tensor {
        std::string name;
        uint64_t sizeBytes = 0;
        uint32_t quantType = 0;
        uint64_t nameHash = 0;
    };

    static CPUInferenceEngine& Instance();
    bool IsLoaded() const { return false; }

    // Stub for execution_scheduler.cpp build
    void TransformerLayer(float* state, float* scratch, int layerIdx,
                          int batchSize, uint32_t deviceId) {
        (void)state; (void)scratch; (void)layerIdx;
        (void)batchSize; (void)deviceId;
    }
};

} // namespace RawrXD
