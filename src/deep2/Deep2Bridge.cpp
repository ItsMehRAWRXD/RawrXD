// ============================================================================
// Deep2Bridge.cpp — Native Deep2 Engine Bridge Implementation
// ============================================================================

#include "Deep2Bridge.hpp"
#include "Deep2Engine.h"
#include "Tokenizer.hpp"
#include "../inference/RawrXD_LlamaNative.h"
#include "../runtime/RawrRuntime.hpp"
#include <cstdio>
#include <chrono>
#include <thread>

namespace rawr {

Deep2Bridge& Deep2Bridge::Get() {
    static Deep2Bridge instance;
    return instance;
}

Deep2Bridge::~Deep2Bridge() = default;

void Deep2Bridge::SetBackend(InferenceBackend backend) {
    if (m_status != EngineStatus::Uninitialized) {
        RawrRuntime::Get().Log(LogLevel::Warn, "Cannot change backend after initialization");
        return;
    }
    m_backend = backend;
}

bool Deep2Bridge::Initialize(const EngineConfig& config) {
    m_config = config;
    m_status = EngineStatus::Initializing;

    RawrRuntime::Get().Log(LogLevel::Info, "Deep2Bridge initializing...");

    if (m_backend == InferenceBackend::LlamaNative) {
        m_llamaBridge = std::make_unique<LlamaNativeBridge>();
        if (!m_llamaBridge->Initialize(nullptr)) {
            RawrRuntime::Get().Log(LogLevel::Error, "LlamaNativeBridge initialization failed");
            m_llamaBridge.reset();
            m_status = EngineStatus::Error;
            return false;
        }
        m_status = EngineStatus::Ready;
        m_sessionId = 1;
        RawrRuntime::Get().Log(LogLevel::Info, "Deep2Bridge ready (LlamaNative backend)");
        return true;
    }

    // Create and initialize the real Deep2Engine
    m_engine = std::make_unique<Deep2::Deep2Engine>();

    Deep2::EngineConfig deep2Cfg;
    deep2Cfg.hiddenDim      = config.hiddenDim;
    deep2Cfg.numLayers      = config.numLayers;
    deep2Cfg.numHeads       = config.numHeads;
    deep2Cfg.numKVHeads     = config.numKVHeads;
    deep2Cfg.headDim        = config.headDim;
    deep2Cfg.vocabSize      = config.vocabSize;
    deep2Cfg.intermediateDim= config.intermediateDim;
    deep2Cfg.maxSeqLen      = static_cast<size_t>(config.contextSize);
    deep2Cfg.useKVCache     = config.useKVCache;
    deep2Cfg.normEps        = config.normEps;
    deep2Cfg.ropeTheta      = config.ropeTheta;
    deep2Cfg.ropeScaling    = config.ropeScaling;

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
    m_llamaBridge.reset();
    m_status = EngineStatus::Uninitialized;
    RawrRuntime::Get().Log(LogLevel::Info, "Deep2Bridge shutdown");
}

bool Deep2Bridge::LoadModel(const char* path) {
    if (m_modelLoaded) {
        UnloadModel();
    }

    m_config.modelPath = path;
    RawrRuntime::Get().Log(LogLevel::Info, "Loading model...");

    if (m_backend == InferenceBackend::LlamaNative) {
        if (!m_llamaBridge) {
            RawrRuntime::Get().Log(LogLevel::Error, "Cannot load model: LlamaNativeBridge not initialized");
            return false;
        }
        int wlen = MultiByteToWideChar(CP_UTF8, 0, path, -1, nullptr, 0);
        std::vector<wchar_t> wpath(wlen);
        MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath.data(), wlen);
        int32_t gpuLayers = m_config.useGPU ? -1 : 0;
        if (!m_llamaBridge->LoadModel(wpath.data(), gpuLayers, static_cast<uint32_t>(m_config.contextSize))) {
            RawrRuntime::Get().Log(LogLevel::Error, "LlamaNative model load failed");
            return false;
        }
        m_modelLoaded = true;
        RawrRuntime::Get().Log(LogLevel::Info, "Model loaded (LlamaNative)");
        return true;
    }

    if (!m_engine) {
        RawrRuntime::Get().Log(LogLevel::Error, "Cannot load model: engine not initialized");
        return false;
    }

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
    if (m_backend == InferenceBackend::LlamaNative && m_llamaBridge) {
        m_llamaBridge->UnloadModel();
    } else if (m_engine) {
        m_engine->unloadModel();
    }
    m_modelLoaded = false;
    RawrRuntime::Get().Log(LogLevel::Info, "Model unloaded");
}

bool Deep2Bridge::Generate(const char* prompt, TokenCallback onToken, ErrorCallback onError) {
    if (!m_modelLoaded || m_generating) return false;

    m_generating = true;
    m_status = EngineStatus::Generating;

    auto start = std::chrono::high_resolution_clock::now();

    if (m_backend == InferenceBackend::LlamaNative) {
        if (!m_llamaBridge) {
            if (onError) onError("LlamaNativeBridge not initialized");
            m_generating = false;
            m_status = EngineStatus::Ready;
            return false;
        }

        auto result = m_llamaBridge->Generate(
            prompt,
            256,  // maxTokens
            m_config.temperature,
            m_config.topP,
            static_cast<int32_t>(m_config.topK)
        );

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        if (!result.success) {
            if (onError) onError(result.error.c_str());
            m_generating = false;
            m_status = EngineStatus::Ready;
            return false;
        }

        if (onToken && !result.text.empty()) {
            onToken(result.text.c_str(), 0);
        }

        m_metrics.totalTokens += result.tokens_generated;
        m_metrics.totalTimeUs += elapsed.count();
        if (elapsed.count() > 0) {
            m_metrics.tokensPerSecond = static_cast<double>(result.tokens_generated) / (elapsed.count() / 1000000.0);
            m_metrics.avgLatencyMs = static_cast<double>(elapsed.count() / 1000.0) / std::max<size_t>(result.tokens_generated, 1);
        }

        m_generating = false;
        m_status = EngineStatus::Ready;
        return result.tokens_generated > 0;
    }

    if (!m_engine) {
        m_generating = false;
        m_status = EngineStatus::Ready;
        return false;
    }

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
