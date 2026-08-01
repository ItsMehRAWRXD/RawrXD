// src/engine/graph/GraphBuilder.hpp
// Structural Layer Resolver — Maps model tensors to linear execution pipeline
#pragma once
#include "ExecutionNode.hpp"
#include "../common_types.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <iostream>

class GraphBuilder {
private:
    std::vector<ExecutionNode> m_linearScheduledQueue;
    std::unordered_map<std::string, std::vector<float>> m_staticPipelineScratchBuffers;

    float* AllocateScratchSpace(const std::string& bufferId, size_t elementCount);

public:
    GraphBuilder() = default;

    bool CompileModelExecutionGraph(
        uint32_t layers,
        uint32_t hiddenSize,
        const std::unordered_map<std::string, TensorInfo>& tensorDb
    );

    const std::vector<ExecutionNode>& GetScheduledQueue() const { return m_linearScheduledQueue; }
    void ResetExecutionGraphState();
};
