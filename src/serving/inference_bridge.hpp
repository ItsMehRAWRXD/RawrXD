#pragma once

/**
 * @file inference_bridge.hpp
 * @brief Bridge between Phase AW Multi-Model Serving and Truth Gate 003 Runtime
 * @details Connects the serving layer to the validated inference runtime
 * @version 14.7.3
 * @date 2026-07-14
 */

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace rawrxd {
namespace serving {

/**
 * @brief Bridge connecting Phase AW serving to Truth Gate 003 inference
 *
 * This adapter allows the multi-model serving layer to execute
 * inference through the validated Sovereign Runtime.
 */
class InferenceBridge {
public:
    /**
     * @brief Load a model through the Sovereign Runtime
     * @param path Path to GGUF model file
     * @param gpu_id GPU device ID (-1 for CPU)
     * @return true if model loaded successfully
     */
    static bool loadModel(const std::string& path, int gpu_id = 0);

    /**
     * @brief Unload a model from memory
     * @param path Path to GGUF model file
     * @return true if model unloaded successfully
     */
    static bool unloadModel(const std::string& path);

    /**
     * @brief Generate tokens from prompt
     * @param prompt Tokenized prompt
     * @param max_tokens Maximum new tokens to generate
     * @return Generated token IDs
     */
    static std::vector<int> generate(
        const std::vector<int>& prompt,
        int max_tokens = 128
    );

    /**
     * @brief Generate with full control
     * @param prompt Tokenized prompt
     * @param max_tokens Maximum new tokens
     * @param temperature Sampling temperature
     * @param top_p Nucleus sampling threshold
     * @param top_k Top-k sampling limit
     * @return Generated token IDs
     */
    static std::vector<int> generateAdvanced(
        const std::vector<int>& prompt,
        int max_tokens,
        float temperature,
        float top_p,
        int top_k
    );

    /**
     * @brief Get latency of last inference call
     * @return Latency in milliseconds
     */
    static float getLastLatencyMs();

    /**
     * @brief Get throughput of last inference call
     * @return Tokens per second
     */
    static float getLastThroughputTps();

    /**
     * @brief Get memory usage for loaded model
     * @return Memory used in bytes
     */
    static size_t getMemoryUsage();

    /**
     * @brief Check if model is loaded
     * @param path Path to GGUF model file
     * @return true if model is currently loaded
     */
    static bool isModelLoaded(const std::string& path);

    /**
     * @brief Get model metadata
     * @param path Path to GGUF model file
     * @return JSON metadata string
     */
    static std::string getModelMetadata(const std::string& path);

    /**
     * @brief Initialize the bridge
     * @return true if initialization successful
     */
    static bool initialize();

    /**
     * @brief Shutdown the bridge
     */
    static void shutdown();

    /**
     * @brief Check if bridge is initialized
     */
    static bool isInitialized();

private:
    static bool initialized_;
    static float last_latency_ms_;
    static float last_throughput_tps_;
    static size_t memory_usage_;
};

/**
 * @brief Telemetry collector for Phase AW integration
 *
 * Collects inference metrics from Truth Gate 003 and
 * feeds them to the serving layer for routing decisions.
 */
class InferenceTelemetry {
public:
    /**
     * @brief Record inference latency
     * @param model_name Model identifier
     * @param latency_ms Latency in milliseconds
     */
    static void recordLatency(const std::string& model_name, float latency_ms);

    /**
     * @brief Record inference throughput
     * @param model_name Model identifier
     * @param tps Tokens per second
     */
    static void recordThroughput(const std::string& model_name, float tps);

    /**
     * @brief Record memory usage
     * @param model_name Model identifier
     * @param bytes Memory used in bytes
     */
    static void recordMemory(const std::string& model_name, size_t bytes);

    /**
     * @brief Get average latency for model
     * @param model_name Model identifier
     * @return Average latency in milliseconds
     */
    static float getAverageLatency(const std::string& model_name);

    /**
     * @brief Get average throughput for model
     * @param model_name Model identifier
     * @return Average tokens per second
     */
    static float getAverageThroughput(const std::string& model_name);

    /**
     * @brief Reset telemetry for model
     * @param model_name Model identifier
     */
    static void reset(const std::string& model_name);
};

/**
 * @brief Resource coordinator for multi-model inference
 *
 * Manages GPU memory and execution resources across
 * multiple concurrent model instances.
 */
class InferenceResourceCoordinator {
public:
    /**
     * @brief Initialize resource coordination
     * @param gpu_count Number of GPUs available
     * @param enable_phase7c Enable Phase 7C memory optimization
     */
    static bool initialize(int gpu_count, bool enable_phase7c = true);

    /**
     * @brief Allocate resources for model
     * @param model_name Model identifier
     * @param memory_required Memory needed in bytes
     * @return GPU ID assigned, or -1 if allocation failed
     */
    static int allocateResources(const std::string& model_name, size_t memory_required);

    /**
     * @brief Release resources for model
     * @param model_name Model identifier
     */
    static void releaseResources(const std::string& model_name);

    /**
     * @brief Get available memory on GPU
     * @param gpu_id GPU device ID
     * @return Available memory in bytes
     */
    static size_t getAvailableMemory(int gpu_id);

    /**
     * @brief Check if resources available for model
     * @param memory_required Memory needed in bytes
     * @return true if resources available
     */
    static bool hasResourcesAvailable(size_t memory_required);
};

} // namespace serving
} // namespace rawrxd