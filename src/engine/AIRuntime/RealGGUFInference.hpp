// src/engine/AIRuntime/RealGGUFInference.hpp
// Real GGUF inference — delegates to CPUInference::CPUInferenceEngine (real.cpp)
// NO SCAFFOLD — this is the real inference pipeline

#pragma once
#include "AIRuntime.hpp"
#include "../../cpu_inference_engine_Clean.h"
#include <string>
#include <vector>
#include <memory>
#include <random>
#include <thread>
#include <atomic>
#include <chrono>

class RealGGUFInference : public IAIRuntime {
private:
    CPUInference::CPUInferenceEngine m_engine;
    InferenceConfig m_config;
    bool m_loaded = false;
    std::atomic<uint64_t> m_totalTokens{0};
    std::atomic<float> m_tokensPerSec{0.0f};
    std::mt19937 m_rng;
    std::chrono::steady_clock::time_point m_lastMeasureTime;
    uint64_t m_lastTokenCount = 0;

public:
    RealGGUFInference();
    ~RealGGUFInference() override;

    bool Initialize(const InferenceConfig& config) override;
    void Shutdown() override;
    InferenceResult Generate(const std::string& prompt) override;
    bool IsModelLoaded() const override { return m_loaded; }

    void RegisterBehavior(const AgentBehavior& behavior) override;
    std::string ExecuteBehavior(const std::string& behaviorName,
                                const std::string& context) override;
    std::string GenerateSceneDescription(const std::string& seed) override;
    std::string GenerateEntityBehavior(const std::string& entityTag) override;
    float GetTokensPerSecond() const override { return m_tokensPerSec.load(); }
    uint64_t GetTotalTokensGenerated() const override { return m_totalTokens.load(); }

private:
    void UpdateTps();
    std::string GenerateText(const std::string& prompt, uint32_t maxTokens);
};
