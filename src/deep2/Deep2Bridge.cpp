// ============================================================================
// Deep2Bridge.cpp — Native Deep2 Engine Bridge Implementation
// ============================================================================

#include "Deep2Bridge.hpp"
#include "Deep2Engine.h"
#include "Tokenizer.hpp"
#include "../runtime/RawrRuntime.hpp"
#include <cstdio>
#include <chrono>
#include <thread>

namespace rawr {

Deep2Bridge& Deep2Bridge::Get() {
    static Deep2Bridge instance;
    return instance;
}

bool Deep2Bridge::Initialize(const EngineConfig& config) {
    m_config = config;
    m_status = EngineStatus::Initializing;

    RawrRuntime::Get().Log(LogLevel::Info, "Deep2Bridge initializing...");

    // Create and initialize the real Deep2Engine
    m_engine = std::make_unique<Deep2::Deep2Engine>();

    Deep2::EngineConfig deep2Cfg;
    deep2Cfg.hiddenDim = 4096;
    deep2Cfg.numLayers = 32;
    deep2Cfg.numHeads = 32;
    deep2Cfg.vocabSize = 32000;
    deep2Cfg.maxSeqLen = static_cast<size_t>(config.contextSize);
    deep2Cfg.useKVCache = config.useKVCache;

    if (!m_engine->initialize(deep2Cfg)) {
        RawrRuntime::Get().Log(LogLevel::Error, "Deep2Engine initialization failed");
        m_engine.reset();
        m_status = EngineStatus::Error;
        return false;
    }

    m_status = EngineStatus::Ready;
    m_sessionId = 1;
    RawrRuntime::Get().Log(LogLevel::Info, "Deep2Bridge ready");
    return true;
}

void Deep2Bridge::Shutdown() {
    if (m_generating) {
        CancelGeneration();
    }
    UnloadModel();
    m_engine.reset();
    m_status = EngineStatus::Uninitialized;
    RawrRuntime::Get().Log(LogLevel::Info, "Deep2Bridge shutdown");
}

bool Deep2Bridge::LoadModel(const char* path) {
    if (m_modelLoaded) {
        UnloadModel();
    }

    if (!m_engine) {
        RawrRuntime::Get().Log(LogLevel::Error, "Cannot load model: engine not initialized");
        return false;
    }

    m_config.modelPath = path;
    RawrRuntime::Get().Log(LogLevel::Info, "Loading model...");

    if (!m_engine->loadModel(path)) {
        RawrRuntime::Get().Log(LogLevel::Error, "Model load failed");
        return false;
    }

    m_modelLoaded = true;
    RawrRuntime::Get().Log(LogLevel::Info, "Model loaded");
    return true;
}

void Deep2Bridge::UnloadModel() {
    if (!m_modelLoaded) return;
    m_modelLoaded = false;
    RawrRuntime::Get().Log(LogLevel::Info, "Model unloaded");
}

bool Deep2Bridge::Generate(const char* prompt, TokenCallback onToken, ErrorCallback onError) {
    if (!m_modelLoaded || m_generating || !m_engine) return false;

    m_generating = true;
    m_status = EngineStatus::Generating;

    auto start = std::chrono::high_resolution_clock::now();

    // Tokenize the prompt
    std::vector<int> promptTokens = m_engine->tokenize(prompt);
    if (promptTokens.empty()) {
        if (onError) onError("Failed to tokenize prompt");
        m_generating = false;
        m_status = EngineStatus::Ready;
        return false;
    }

    // Allocate output buffer
    const size_t maxOutputLen = 256;
    std::vector<int> outputTokens(maxOutputLen);
    Deep2::InferenceStats stats{};

    // Invoke the real Deep2Engine generation
    size_t generated = m_engine->generate(
        promptTokens.data(), promptTokens.size(),
        outputTokens.data(), maxOutputLen,
        &stats,
        [&](int tokenId) -> bool {
            if (!m_generating) return false; // cancelled
            std::string tokenText = m_engine->detokenize(std::vector<int>{tokenId});
            if (onToken) onToken(tokenText.c_str(), static_cast<uint32_t>(stats.tokensGenerated));
            return true;
        }
    );

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    m_metrics.totalTokens += generated;
    m_metrics.totalTimeUs += elapsed.count();
    if (elapsed.count() > 0) {
        m_metrics.tokensPerSecond = static_cast<double>(generated) / (elapsed.count() / 1000000.0);
        m_metrics.avgLatencyMs = static_cast<double>(elapsed.count() / 1000.0) / std::max<size_t>(generated, 1);
    }

    m_generating = false;
    m_status = EngineStatus::Ready;
    return generated > 0;
}

bool Deep2Bridge::GenerateStream(const char* prompt, TokenCallback onToken, ErrorCallback onError) {
    return Generate(prompt, onToken, onError);
}

void Deep2Bridge::CancelGeneration() {
    m_generating = false;
    m_status = EngineStatus::Ready;
}

Deep2Bridge::Metrics Deep2Bridge::GetMetrics() const {
    return m_metrics;
}

void Deep2Bridge::ResetSession() {
    m_sessionId++;
    m_metrics = {};
    RawrRuntime::Get().Log(LogLevel::Info, "Session reset");
}

} // namespace rawr
