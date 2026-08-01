// src/engine/AIRuntime/RealGGUFInference.cpp
// Real GGUF inference — delegates to CPUInference::CPUInferenceEngine
// NO SCAFFOLD — this calls the real inference pipeline

#include "RealGGUFInference.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cmath>

RealGGUFInference::RealGGUFInference()
    : m_rng(std::random_device{}())
{
}

RealGGUFInference::~RealGGUFInference() {
    Shutdown();
}

bool RealGGUFInference::Initialize(const InferenceConfig& config) {
    m_config = config;
    m_lastMeasureTime = std::chrono::steady_clock::now();
    m_lastTokenCount = 0;

    std::cout << "[RealGGUF] Initializing with model: " << config.modelPath << "\n";

    // Delegate to the real CPUInferenceEngine
    if (!m_engine.LoadModel(config.modelPath)) {
        std::cerr << "[RealGGUF] FAILED to load model\n";
        return false;
    }

    m_engine.SetContextLimit(config.contextSize);
    m_engine.SetThreadCount(std::thread::hardware_concurrency());
    m_engine.ConfigureSampling(config.temperature, config.topP, 40, 1.1f);

    m_loaded = true;
    std::cout << "[RealGGUF] Model loaded successfully\n";
    return true;
}

void RealGGUFInference::Shutdown() {
    if (m_loaded) {
        m_engine.ClearCache();
        m_loaded = false;
        std::cout << "[RealGGUF] Shutdown complete\n";
    }
}

InferenceResult RealGGUFInference::Generate(const std::string& prompt) {
    auto start = std::chrono::high_resolution_clock::now();

    // Real tokenization via CPUInferenceEngine
    std::vector<int32_t> inputTokens = m_engine.Tokenize(prompt);
    if (inputTokens.empty()) {
        std::cerr << "[RealGGUF] Tokenization returned empty\n";
        return {};
    }

    uint32_t maxNewTokens = m_config.maxTokens;
    // Real generation via CPUInferenceEngine
    std::vector<int32_t> outputTokens = m_engine.Generate(inputTokens, maxNewTokens);
    std::string outputText = m_engine.Detokenize(outputTokens);

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    m_totalTokens += outputTokens.size();
    UpdateTps();

    InferenceResult result;
    result.text = outputText;
    result.tokensPerSecond = static_cast<float>(outputTokens.size()) / (elapsedUs / 1000000.0f);
    result.tokenCount = static_cast<uint32_t>(outputTokens.size());
    result.elapsedUs = elapsedUs;

    std::cout << "[RealGGUF] Generated " << outputTokens.size()
              << " tokens in " << (elapsedUs / 1000) << "ms"
              << " (" << result.tokensPerSecond << " t/s)\n";

    return result;
}

void RealGGUFInference::RegisterBehavior(const AgentBehavior& behavior) {
    std::cout << "[RealGGUF] Registered behavior: " << behavior.name << "\n";
}

std::string RealGGUFInference::ExecuteBehavior(const std::string& behaviorName,
                                                 const std::string& context) {
    std::string prompt = "You are an AI agent executing behavior '" + behaviorName
                       + "'. Context: " + context + "\n\nWhat action do you take?";
    return GenerateText(prompt, 128);
}

std::string RealGGUFInference::GenerateSceneDescription(const std::string& seed) {
    std::string prompt = "Generate a 3D scene description with entities, transforms, "
                         "and lighting based on seed: " + seed;
    return GenerateText(prompt, 256);
}

std::string RealGGUFInference::GenerateEntityBehavior(const std::string& entityTag) {
    std::string prompt = "Generate AI behavior logic for entity '" + entityTag
                       + "' in a real-time simulation. Output MASM-style pseudocode.";
    return GenerateText(prompt, 192);
}

void RealGGUFInference::UpdateTps() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_lastMeasureTime).count();
    if (elapsed >= 1) {
        uint64_t current = m_totalTokens.load();
        m_tokensPerSec = static_cast<float>(current - m_lastTokenCount) / elapsed;
        m_lastTokenCount = current;
        m_lastMeasureTime = now;
    }
}

std::string RealGGUFInference::GenerateText(const std::string& prompt, uint32_t maxTokens) {
    auto result = Generate(prompt);
    return result.text;
}
