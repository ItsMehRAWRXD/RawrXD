/**
 * @file MockAgenticEngine.h
 * @brief Mock implementation of minimal IAgenticEngine
 * 
 * L3 verified - used to validate Core orchestration.
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include "IAgenticEngine.h"

namespace RawrXD {
namespace Agentic {

class MockAgenticEngine : public IAgenticEngine {
public:
    ~MockAgenticEngine() override = default;

    bool Initialize() override {
        m_initialized = true;
        return true;
    }

    void Shutdown() override {
        m_initialized = false;
        m_modelLoaded = false;
    }

    bool LoadModel(const std::string& path) override {
        m_modelPath = path;
        m_modelLoaded = true;
        return true;
    }

    bool IsModelLoaded() const override {
        return m_modelLoaded;
    }

    std::vector<int> Tokenize(const std::string& text) override {
        std::vector<int> tokens;
        for (char c : text) {
            tokens.push_back(static_cast<int>(c));
        }
        return tokens;
    }

    std::string Generate(const std::vector<int>& tokens, size_t maxTokens) override {
        (void)tokens;
        // Mock: return deterministic "generated" text
        return "[MOCK] Generated " + std::to_string(maxTokens) + " tokens";
    }

private:
    bool m_initialized = false;
    bool m_modelLoaded = false;
    std::string m_modelPath;
};

} // namespace Agentic
} // namespace RawrXD
