#pragma once
/**
 * @file GenerationBouncer.hpp
 * @brief Unified entry point for all generation requests
 * 
 * Consolidates 28+ generate() paths into single canonical pipeline:
 *   Prompt → Tokenize → Embed → Forward → Sample → Decode → Stream
 * 
 * @copyright RawrXD 2026
 */

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <chrono>

namespace RawrXD {

// Forward declarations
class InferenceEngine;
class Tokenizer;
class ModelContext;
class TransformerForward;
class Sampler;
class TokenStreamer;

/**
 * @brief Generation request parameters
 */
struct GenerationRequest {
    std::string prompt;
    int max_tokens = 256;
    float temperature = 0.7f;
    float top_p = 0.9f;
    int top_k = 40;
    float repetition_penalty = 1.1f;
    bool stream = false;
    std::function<void(const std::string&)> on_token = nullptr;
};

/**
 * @brief Generation result with metrics
 */
struct GenerationResult {
    std::string text;
    std::vector<int> tokens;
    int tokens_generated = 0;
    double tokens_per_second = 0.0;
    double time_to_first_token_ms = 0.0;
    bool success = false;
    std::string error;
};

/**
 * @brief Unified Generation Bouncer
 * 
 * Single entry point that routes all generation requests through
 * canonical pipeline. Replaces 28+ fragmented generate() implementations.
 * 
 * Usage:
 * ```cpp
 * GenerationBouncer bouncer;
 * bouncer.Initialize("model.gguf");
 * 
 * GenerationRequest req;
 * req.prompt = "Explain quantum computing";
 * req.max_tokens = 100;
 * 
 * GenerationResult result = bouncer.Generate(req);
 * std::cout << result.text << std::endl;
 * ```
 */
class GenerationBouncer {
public:
    GenerationBouncer();
    ~GenerationBouncer();

    /**
     * @brief Initialize with GGUF model path
     * @param model_path Path to GGUF model file
     * @return true if model loaded successfully
     */
    bool Initialize(const std::string& model_path);

    /**
     * @brief Unload model and release resources
     */
    void Shutdown();

    /**
     * @brief Check if model is loaded and ready
     */
    bool IsReady() const;

    /**
     * @brief Generate text from prompt (canonical entry point)
     * @param req Generation request parameters
     * @return Generation result with text and metrics
     */
    GenerationResult Generate(const GenerationRequest& req);

    /**
     * @brief Generate with streaming callback
     * @param req Generation request (must have on_token callback)
     * @return Generation result (text will be empty, tokens streamed via callback)
     */
    GenerationResult GenerateStreaming(GenerationRequest req);

    /**
     * @brief Get model statistics
     */
    struct ModelStats {
        size_t num_parameters = 0;
        size_t num_layers = 0;
        size_t vocab_size = 0;
        size_t context_length = 0;
        std::string model_type;
    };
    ModelStats GetModelStats() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;

    // Prevent copying
    GenerationBouncer(const GenerationBouncer&) = delete;
    GenerationBouncer& operator=(const GenerationBouncer&) = delete;
};

} // namespace RawrXD
