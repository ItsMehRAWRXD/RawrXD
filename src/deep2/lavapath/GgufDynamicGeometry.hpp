// GgufDynamicGeometry.hpp — fail-closed GGUF → session arch geometry + static residency frontier
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

    // Static residency frontier (computed from tensor directory, no weight payload read)
    // All byte counts are ROM bytes as encoded in GGUF tensor directory.
    uint64_t totalWeightBytes = 0;           // Σ encoded bytes of all tensors
    uint64_t embedBytes = 0;                 // token_embd.weight (ROM)
    uint64_t outputHeadBytes = 0;            // output.weight (ROM, 0 if tied)
    uint64_t maxLayerBytes = 0;              // max Σ bytes for any single layer
    uint64_t minLayerBytes = 0;              // min Σ bytes for any single layer
    uint64_t kvCacheBytesPerToken = 0;       // KV cache @ fp16 per token (if metadata available)

    // M_min policy frontier
    // M_MIN_POLICY_PIN_EMBED_AND_HEAD = 0: embed + head pinned (standard tied/untied)
    // M_MIN_POLICY_PIN_EMBED_ONLY   = 1: only embed pinned, head streamable
    // M_MIN_POLICY_FULLY_STREAMABLE = 2: nothing pinned, all streamed (theoretical floor)
    uint64_t mMinPinEmbedAndHead = 0;        // M_min under PIN_EMBED_AND_HEAD
    uint64_t mMinPinEmbedOnly = 0;           // M_min under PIN_EMBED_ONLY
    uint64_t mMinFullyStreamable = 0;        // M_min under FULLY_STREAMABLE

    // Ring depth frontier: peak bytes for k=1,2,3,4,6,8
    // peak(k) = policy_floor + k * maxLayerBytes
    uint64_t ringK1 = 0;
    uint64_t ringK2 = 0;
    uint64_t ringK3 = 0;
    uint64_t ringK4 = 0;
    uint64_t ringK6 = 0;
    uint64_t ringK8 = 0;

    // File integrity / truncation verdict
    // 0 = UNVERIFIED, 1 = COMPLETE, 2 = TRUNCATED, 3 = OVERSIZE, 4 = UNKNOWN_TYPES_WEAKENED
    uint8_t integrityVerdict = 0;
    uint64_t actualFileBytes = 0;
    uint64_t requiredFileBytes = 0;
    uint64_t shortfallBytes = 0;
    uint8_t unknownTypeCount = 0;            // tensors with undecoded GGML type
    uint8_t overlappingTensors = 0;
    uint8_t misalignedOffsets = 0;
    uint8_t offsetOverflows = 0;
};

// Parse path; on success geometry is immutable session authority.
// Returns true only when GGUF_DYNAMIC_GEOMETRY_001 would be PASS.
bool GgufResolveDynamicGeometry(const char* path, GgufDynamicGeometry* out);

// Compute static residency frontier from already-parsed tensor directory.
// Requires: out->tensorCount > 0, tensor metadata populated in Scratch.
// This is a second pass over the same file; returns true on success.
bool GgufComputeStaticResidency(const char* path, GgufDynamicGeometry* out);

// Integrity gate: validates every tensor extent fits within the file BEFORE
// any weight payload is read. Returns true iff ALL_TENSOR_EXTENTS_PROVEN=1.
bool GgufVerifyRomIntegrity(const char* path, GgufDynamicGeometry* out);

} // namespace Deep2
