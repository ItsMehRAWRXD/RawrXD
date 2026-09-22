#pragma once
/* ProductionProfiler — stub */
#include <cstdint>
#include <string>
namespace Deep2 {
struct TokenProfile {
    uint32_t tokenId = 0;
    float latencyMs = 0.0f;
    float tflops = 0.0f;
    std::string kernelName;
};
class ProductionProfiler {};
} // namespace Deep2
