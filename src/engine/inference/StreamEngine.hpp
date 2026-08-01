// src/engine/inference/StreamEngine.hpp
// Multi-Threaded Inference Manager — Async token stream generation
#pragma once
#include "../graph/GraphBuilder.hpp"
#include "../kernels/SovereignMathCore.hpp"
#include "../common_types.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <atomic>
#include <thread>
#include <memory>
#include <cstdint>

using TokenCallback = std::function<void(uint32_t tokenId, const std::string& tokenText)>;

class StreamEngine {
private:
    GraphBuilder m_graphBuilder;
    std::unordered_map<std::string, TensorInfo> m_tensorDb;
    std::atomic<bool> m_isGenerationLoopActive;
    std::thread m_workerThread;

    uint32_t m_layerCount;
    uint32_t m_hiddenSize;
    uint32_t m_vocabSize;

    void InferenceWorkerThreadLoop(std::vector<uint32_t> seedTokens,
                                    float temperature,
                                    TokenCallback callback);
    std::string MapTokenToPrimitiveString(uint32_t tokenId);

public:
    StreamEngine();
    ~StreamEngine();

    bool LoadEngineInfrastructure(const std::wstring& ggufFilePath,
                                   uint32_t layers,
                                   uint32_t hiddenSize,
                                   uint32_t vocabSize);
    void SetTensorDb(const std::unordered_map<std::string, TensorInfo>& db) { m_tensorDb = db; }
    void TriggerAsyncGenerationStream(const std::vector<uint32_t>& inputTokens,
                                       float temperature,
                                       TokenCallback callback);
    void HaltActiveStream();
    bool IsEngineProcessing() const { return m_isGenerationLoopActive.load(); }
};
