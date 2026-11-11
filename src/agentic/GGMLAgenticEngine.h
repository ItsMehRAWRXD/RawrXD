/**
 * @file GGMLAgenticEngine.h
 * @brief Minimal GGML backend implementing IAgenticEngine
 * 
 * L4 Target: Load Phi-3-mini GGUF, generate one deterministic token.
 * 
 * Design rules:
 *   - NO AppState
 *   - NO cpu_inference_engine.h
 *   - NO C++20 features
 *   - Direct GGML calls only
 * 
 * Dependencies:
 *   - ggml.h (C API)
 *   - gguf_loader.h (existing)
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include "IAgenticEngine.h"
#include <memory>
#include <vector>
#include <string>

namespace RawrXD {
namespace Agentic {

/**
 * @brief GGML-backed implementation of IAgenticEngine
 * 
 * Minimal surface area for L4 validation:
 *   Initialize → LoadModel → Tokenize → Generate(1 token)
 * 
 * Uses PIMPL pattern to hide GGML dependencies from header.
 */
class GGMLAgenticEngine : public IAgenticEngine {
public:
    GGMLAgenticEngine();
    ~GGMLAgenticEngine() override;

    // Disable copy/move - heavy GGML context
    GGMLAgenticEngine(const GGMLAgenticEngine&) = delete;
    GGMLAgenticEngine& operator=(const GGMLAgenticEngine&) = delete;

    // ============================================================================
    // IAgenticEngine Implementation
    // ============================================================================
    
    bool Initialize() override;
    void Shutdown() override;
    
    bool LoadModel(const std::string& path) override;
    bool IsModelLoaded() const override;
    
    std::vector<int> Tokenize(const std::string& text) override;
    
    std::string Generate(const std::vector<int>& tokens, 
                        size_t maxTokens) override;

    // ============================================================================
    // L4 Diagnostic Access (for validation only, not part of contract)
    // ============================================================================
    
    /**
     * @brief Get last error message
     */
    std::string GetLastError() const { return m_lastError; }
    
    /**
     * @brief Check if GGML context is valid
     */
    bool IsContextValid() const;

private:
    // PIMPL - hide GGML implementation details
    class Impl;
    std::unique_ptr<Impl> m_impl;
    
    // Model state (lightweight, can stay here)
    std::string m_modelPath;
    bool m_initialized = false;
    bool m_modelLoaded = false;
    std::string m_lastError;
    bool LoadGGUF(const std::string& path);
    void UnloadModelInternal();
    
    // Single token generation (the L4 milestone)
    int GenerateSingleToken(const std::vector<int>& promptTokens);
};

} // namespace Agentic
} // namespace RawrXD
