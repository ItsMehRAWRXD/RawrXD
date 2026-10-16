#pragma once

// Deep2InferenceService.hpp - Shared, lifecycle-managed inference service
// Ensures a single Deep2Engine instance across all components (CLI, API, IDE,
// agents) to prevent redundant model loads and VRAM contention.
//
// Concurrency:
//   - A single generationMutex serializes all generateText() calls so the
//     shared Deep2Engine is never invoked concurrently.
//   - initMutex_ protects model load/unload transitions.
//   - generationActive_ indicates a generation is in progress; cancellation
//     sets cancelGeneration_ which the engine checks between tokens.

#include "Deep2Engine.h"
#include <mutex>
#include <atomic>
#include <string>
#include <memory>

namespace RawrXD {

class Deep2InferenceService {
public:
    // Get the singleton instance
    static Deep2InferenceService& instance();

    // Initialize the shared engine (idempotent - safe to call multiple times)
    bool initialize(const Deep2::EngineConfig& config);

    // Load a model into the shared engine (idempotent if same path)
    bool loadModel(const std::string& ggufPath);

    // Check if engine is initialized
    bool isInitialized() const { return engineInitialized_.load(); }

    // Check if a model is loaded
    bool isModelLoaded() const { return modelLoaded_.load(); }

    // Get model path
    const std::string& modelPath() const { return modelPath_; }

    // Generate text via the shared engine (serialized via generationMutex_)
    std::string generateText(const std::string& prompt, size_t maxTokens = 256);

    // Request cancellation of in-progress generation
    void requestCancellation();

    // Check if cancellation was requested (for engine polling)
    bool cancellationRequested() const;

    // Reset cancellation flag before starting a new generation
    void clearCancellation();

    // Configure generation on the shared engine
    void configureGeneration(const Deep2::GenerationOptions& options);

    // Shutdown the service (unload model, release engine). Blocks until any
    // in-progress generation completes.
    void shutdown();

private:
    Deep2InferenceService() = default;
    ~Deep2InferenceService() = default;
    Deep2InferenceService(const Deep2InferenceService&) = delete;
    Deep2InferenceService& operator=(const Deep2InferenceService&) = delete;

    Deep2::Deep2Engine engine_;
    std::atomic<bool> engineInitialized_{false};
    std::atomic<bool> modelLoaded_{false};
    std::atomic<bool> cancelGeneration_{false};
    std::atomic<bool> generationActive_{false};
    std::string modelPath_;
    mutable std::mutex initMutex_;      // Protects load/unload/initialize/shutdown
    mutable std::mutex generationMutex_; // Serializes concurrent generateText()
};

} // namespace RawrXD
