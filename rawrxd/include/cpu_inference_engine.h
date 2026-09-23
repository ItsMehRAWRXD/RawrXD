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
};

} // namespace RawrXD
