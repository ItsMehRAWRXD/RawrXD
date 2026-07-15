#pragma once

/**
 * @file offline_runtime.hpp
 * @brief Lightweight inference runtime for edge devices
 * @details Minimal memory footprint, CPU-optimized, no GPU required
 * @version 14.7.3
 * @date 2026-07-14
 */

#include <cstring>
#include <vector>
#include <cstdint>
#include <memory>
#include <optional>

namespace rawrxd {
namespace edge {

/**
 * @brief Runtime configuration
 */
struct RuntimeConfig {
    size_t max_memory_mb = 2048;        ///< Maximum memory in MB
    size_t max_context_length = 2048;   ///< Maximum context length
    int num_threads = 4;                ///< Number of CPU threads
    bool use_quantized_kernels = true;  ///< Use INT8/INT4 kernels
    bool enable_flash_attention = false; ///< Flash attention (if available)
    bool streaming_generation = true;   ///< Stream tokens as generated
};

/**
 * @brief Generation configuration
 */
struct GenerationConfig {
    int max_new_tokens = 128;           ///< Maximum tokens to generate
    float temperature = 0.8f;           ///< Sampling temperature
    float top_p = 0.95f;                ///< Nucleus sampling threshold
    int top_k = 40;                     ///< Top-k sampling limit
    float repetition_penalty = 1.0f;     ///< Repetition penalty
    bool stop_on_eos = true;            ///< Stop at EOS token
    std::vector<int> stop_tokens;       ///< Additional stop tokens
};

/**
 * @brief Runtime statistics
 */
struct RuntimeStats {
    size_t memory_used;                 ///< Current memory usage
    size_t peak_memory;                 ///< Peak memory usage
    float avg_inference_time_ms;        ///< Average inference latency
    float tokens_per_second;            ///< Generation throughput
    int models_loaded;                  ///< Number of loaded models
    int cache_hits;                     ///< Cache hit count
    int cache_misses;                   ///< Cache miss count
};

/**
 * @brief Model loading result
 */
struct ModelLoadResult {
    bool success;
    std::string model_id;
    size_t memory_required;
    std::string error_message;
};

/**
 * @brief Generation result
 */
struct GenerationResult {
    std::vector<int> tokens;            ///< Generated token IDs
    int prompt_tokens;                  ///< Number of prompt tokens
    int completion_tokens;            ///< Number of completion tokens
    float total_time_ms;                ///< Total generation time
    float tokens_per_second;            ///< Throughput
    bool finished;                      ///< Generation completed
    std::string finish_reason;          ///< Reason for stopping
};

/**
 * @brief Offline inference runtime
 *
 * Lightweight runtime optimized for edge devices:
 * - Minimal memory footprint (< 2GB)
 * - CPU-optimized kernels
 * - Quantized operations (INT8/INT4)
 * - Streaming generation
 */
class OfflineInferenceRuntime {
public:
    OfflineInferenceRuntime();
    ~OfflineInferenceRuntime();

    /**
     * @brief Initialize runtime
     * @param config Runtime configuration
     * @return true if initialization successful
     */
    bool initialize(const RuntimeConfig& config);

    /**
     * @brief Load model into runtime
     * @param model_id Unique model identifier
     * @param model_data Compressed model binary
     * @return Load result with status
     */
    ModelLoadResult loadModel(
        const std::string& model_id,
        const std::vector<uint8_t>& model_data
    );

    /**
     * @brief Load model from cache
     * @param cache_manager Cache manager to load from
     * @param model_id Model identifier
     * @return Load result with status
     */
    ModelLoadResult loadFromCache(
        class EdgeCacheManager& cache_manager,
        const std::string& model_id
    );

    /**
     * @brief Unload model
     * @param model_id Model identifier
     * @return true if unloaded
     */
    bool unloadModel(const std::string& model_id);

    /**
     * @brief Check if model is loaded
     * @param model_id Model identifier
     * @return true if loaded and ready
     */
    bool isModelLoaded(const std::string& model_id) const;

    /**
     * @brief Generate tokens from prompt
     * @param model_id Model to use
     * @param prompt Tokenized prompt
     * @param config Generation configuration
     * @return Generation result
     */
    GenerationResult generate(
        const std::string& model_id,
        const std::vector<int>& prompt,
        const GenerationConfig& config
    );

    /**
     * @brief Generate with callback for streaming
     * @param model_id Model to use
     * @param prompt Tokenized prompt
     * @param config Generation configuration
     * @param callback Called for each generated token
     * @return Generation result
     */
    GenerationResult generateStreaming(
        const std::string& model_id,
        const std::vector<int>& prompt,
        const GenerationConfig& config,
        std::function<void(int, float)> callback
    );

    /**
     * @brief Get runtime statistics
     * @return Current statistics
     */
    RuntimeStats getStats() const;

    /**
     * @brief Reset statistics
     */
    void resetStats();

    /**
     * @brief Check if runtime is initialized
     */
    bool isInitialized() const;

    /**
     * @brief Get loaded model IDs
     * @return Vector of loaded model IDs
     */
    std::vector<std::string> getLoadedModels() const;

    /**
     * @brief Get memory usage
     * @return Current memory in bytes
     */
    size_t getMemoryUsage() const;

    /**
     * @brief Clear all loaded models
     */
    void clearAllModels();

    /**
     * @brief Set memory limit
     * @param max_memory_mb Maximum memory in MB
     */
    void setMemoryLimit(size_t max_memory_mb);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Token streaming callback
 */
using TokenCallback = std::function<void(int token_id, bool is_last)>;

/**
 * @brief Batch generation for multiple prompts
 */
class BatchGenerator {
public:
    /**
     * @brief Generate for multiple prompts
     * @param runtime Runtime to use
     * @param model_id Model to use
     * @param prompts Vector of tokenized prompts
     * @param config Generation configuration
     * @return Vector of generation results
     */
    static std::vector<GenerationResult> generateBatch(
        OfflineInferenceRuntime& runtime,
        const std::string& model_id,
        const std::vector<std::vector<int>>& prompts,
        const GenerationConfig& config
    );
};

} // namespace edge
} // namespace rawrxd
