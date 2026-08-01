// src/engine/graph/GraphBuilder.cpp
// Linear Sequencer Pipeline — Pre-allocates scratch buffers, builds node chain
#include "GraphBuilder.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>

float* GraphBuilder::AllocateScratchSpace(const std::string& bufferId, size_t elementCount) {
    if (m_staticPipelineScratchBuffers.find(bufferId) == m_staticPipelineScratchBuffers.end()) {
        m_staticPipelineScratchBuffers[bufferId].assign(elementCount, 0.0f);
    }
    return m_staticPipelineScratchBuffers[bufferId].data();
}

void GraphBuilder::ResetExecutionGraphState() {
    m_linearScheduledQueue.clear();
}

bool GraphBuilder::CompileModelExecutionGraph(
    uint32_t layers,
    uint32_t hiddenSize,
    const std::unordered_map<std::string, TensorInfo>& tensorDb
) {
    ResetExecutionGraphState();
    std::cout << "[GraphBuilder] Compiling execution graph: "
              << layers << " layers, " << hiddenSize << " hidden dim\n";

    // Pre-allocate scratch buffers for the pipeline
    AllocateScratchSpace("input", hiddenSize);
    AllocateScratchSpace("norm", hiddenSize);
    AllocateScratchSpace("qkv", hiddenSize * 3);
    AllocateScratchSpace("attn_out", hiddenSize);
    AllocateScratchSpace("ffn_gate", hiddenSize);
    AllocateScratchSpace("ffn_up", hiddenSize);
    AllocateScratchSpace("ffn_down", hiddenSize);
    AllocateScratchSpace("logits", hiddenSize);

    // Build per-layer execution nodes
    for (uint32_t layer = 0; layer < layers; ++layer) {
        // RMS Norm node
        ExecutionNode normNode;
        normNode.nodeName = "Layer_" + std::to_string(layer) + "_RmsNorm";
        normNode.operation = LayerOp::RmsNormTensors;
        normNode.dimensions = { hiddenSize };
        normNode.inputBufferView = { m_staticPipelineScratchBuffers["input"].data(), hiddenSize };
        normNode.outputBufferView = { m_staticPipelineScratchBuffers["norm"].data(), hiddenSize };

        // Look up weight tensor
        std::string normKey = "blk." + std::to_string(layer) + ".attn_norm.weight";
        auto it = tensorDb.find(normKey);
        if (it != tensorDb.end()) {
            normNode.weightDataRef = &it->second;
            normNode.weightType = static_cast<GgufType>(it->second.type);
        }
        m_linearScheduledQueue.push_back(std::move(normNode));

        // Attention QKV node
        ExecutionNode qkvNode;
        qkvNode.nodeName = "Layer_" + std::to_string(layer) + "_Attention_QKV";
        qkvNode.operation = LayerOp::AttentionQKV;
        qkvNode.dimensions = { hiddenSize, hiddenSize * 3 };
        qkvNode.inputBufferView = { m_staticPipelineScratchBuffers["norm"].data(), hiddenSize };
        qkvNode.outputBufferView = { m_staticPipelineScratchBuffers["qkv"].data(), hiddenSize * 3 };

        std::string qkvKey = "blk." + std::to_string(layer) + ".attn_qkv.weight";
        it = tensorDb.find(qkvKey);
        if (it != tensorDb.end()) {
            qkvNode.weightDataRef = &it->second;
            qkvNode.weightType = static_cast<GgufType>(it->second.type);
        }
        m_linearScheduledQueue.push_back(std::move(qkvNode));

        // Attention Output node
        ExecutionNode attnOutNode;
        attnOutNode.nodeName = "Layer_" + std::to_string(layer) + "_Attention_Out";
        attnOutNode.operation = LayerOp::AttentionOut;
        attnOutNode.dimensions = { hiddenSize, hiddenSize };
        attnOutNode.inputBufferView = { m_staticPipelineScratchBuffers["qkv"].data(), hiddenSize * 3 };
        attnOutNode.outputBufferView = { m_staticPipelineScratchBuffers["attn_out"].data(), hiddenSize };

        std::string attnOutKey = "blk." + std::to_string(layer) + ".attn_out.weight";
        it = tensorDb.find(attnOutKey);
        if (it != tensorDb.end()) {
            attnOutNode.weightDataRef = &it->second;
            attnOutNode.weightType = static_cast<GgufType>(it->second.type);
        }
        m_linearScheduledQueue.push_back(std::move(attnOutNode));

        // FFN Gate + Up projection node
        ExecutionNode ffnGateUpNode;
        ffnGateUpNode.nodeName = "Layer_" + std::to_string(layer) + "_FFN_GateUp";
        ffnGateUpNode.operation = LayerOp::FfnGateUp;
        ffnGateUpNode.dimensions = { hiddenSize, hiddenSize * 2 };
        ffnGateUpNode.inputBufferView = { m_staticPipelineScratchBuffers["attn_out"].data(), hiddenSize };
        ffnGateUpNode.outputBufferView = { m_staticPipelineScratchBuffers["ffn_gate"].data(), hiddenSize * 2 };

        std::string ffnGateKey = "blk." + std::to_string(layer) + ".ffn_gate.weight";
        it = tensorDb.find(ffnGateKey);
        if (it != tensorDb.end()) {
            ffnGateUpNode.weightDataRef = &it->second;
            ffnGateUpNode.weightType = static_cast<GgufType>(it->second.type);
        }
        m_linearScheduledQueue.push_back(std::move(ffnGateUpNode));

        // FFN Down projection node
        ExecutionNode ffnDownNode;
        ffnDownNode.nodeName = "Layer_" + std::to_string(layer) + "_FFN_Down";
        ffnDownNode.operation = LayerOp::FfnDownProjection;
        ffnDownNode.dimensions = { hiddenSize, hiddenSize };
        ffnDownNode.inputBufferView = { m_staticPipelineScratchBuffers["ffn_gate"].data(), hiddenSize * 2 };
        ffnDownNode.outputBufferView = { m_staticPipelineScratchBuffers["ffn_down"].data(), hiddenSize };

        std::string ffnDownKey = "blk." + std::to_string(layer) + ".ffn_down.weight";
        it = tensorDb.find(ffnDownKey);
        if (it != tensorDb.end()) {
            ffnDownNode.weightDataRef = &it->second;
            ffnDownNode.weightType = static_cast<GgufType>(it->second.type);
        }
        m_linearScheduledQueue.push_back(std::move(ffnDownNode));
    }

    // Output projection node
    ExecutionNode outputNode;
    outputNode.nodeName = "Output_Logits";
    outputNode.operation = LayerOp::OutputClassLogits;
    outputNode.dimensions = { hiddenSize, hiddenSize };
    outputNode.inputBufferView = { m_staticPipelineScratchBuffers["ffn_down"].data(), hiddenSize };
    outputNode.outputBufferView = { m_staticPipelineScratchBuffers["logits"].data(), hiddenSize };

    auto it = tensorDb.find("output.weight");
    if (it != tensorDb.end()) {
        outputNode.weightDataRef = &it->second;
        outputNode.weightType = static_cast<GgufType>(it->second.type);
    }
    m_linearScheduledQueue.push_back(std::move(outputNode));

    std::cout << "[GraphBuilder] Compiled " << m_linearScheduledQueue.size()
              << " execution nodes, " << m_staticPipelineScratchBuffers.size()
              << " scratch buffers\n";
    return !m_linearScheduledQueue.empty();
}
