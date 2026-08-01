// src/engine/graph/ExecutionNode.hpp
// Execution Graph Node Primitives — Zero-Allocation Pipeline Definitions
#pragma once
#include "../kernels/SovereignMathCore.hpp"
#include <string>
#include <vector>
#include <cstdint>

enum class LayerOp : uint32_t {
    TokenEmbedding       = 0,
    RmsNormTensors       = 1,
    AttentionQKV         = 2,
    AttentionOut         = 3,
    FfnGateUp            = 4,
    FfnDownProjection    = 5,
    OutputClassLogits    = 6
};

struct ComputeBufferView {
    float* dataPointer   = nullptr;
    size_t elementCount  = 0;
};

struct ExecutionNode {
    std::string          nodeName;
    LayerOp              operation;
    const void*          weightDataRef  = nullptr;
    GgufType             weightType     = GgufType::Unknown;
    std::vector<uint64_t> dimensions;

    // Non-owning pipeline data views
    ComputeBufferView    inputBufferView;
    ComputeBufferView    outputBufferView;
};
