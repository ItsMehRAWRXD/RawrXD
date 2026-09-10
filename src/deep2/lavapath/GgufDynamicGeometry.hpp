// GgufDynamicGeometry.hpp — fail-closed GGUF → session arch geometry
#pragma once
#include <cstdint>
#include <cstring>

#define RAWR_NO_STATIC_MODEL_GEOMETRY 1
#define RAWR_GGUF_DYNAMIC_GEOMETRY_001 1

namespace Deep2 {

struct GgufDynamicGeometry {
    uint32_t version = 0;
    uint64_t tensorCount = 0;
    uint64_t metadataCount = 0;
    char arch[64] = {};
    uint32_t layers = 0;
    uint32_t hidden = 0;
    uint32_t ffn = 0;
    uint32_t heads = 0;
    uint32_t kvHeads = 0;
    uint32_t headDim = 0;
    uint32_t context = 0;
    uint32_t ropeDim = 0;
    float rmsEps = 0.f;
    float ropeBase = 0.f;
    float ropeScaling = 0.f;
    uint8_t headDimDerived = 0;
    uint8_t ropeScalingPresent = 0;
    uint8_t magicOk = 0;
    uint8_t boundsOk = 0;
    uint8_t consistent = 0;
    uint8_t authority = 0;
    char blockedAt[32] = {};
    char reason[128] = {};
};

// Parse path; on success geometry is immutable session authority.
// Returns true only when GGUF_DYNAMIC_GEOMETRY_001 would be PASS.
bool GgufResolveDynamicGeometry(const char* path, GgufDynamicGeometry* out);

} // namespace Deep2
