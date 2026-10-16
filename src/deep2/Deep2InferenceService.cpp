// Deep2InferenceService.cpp - Shared, lifecycle-managed inference service

#include "Deep2InferenceService.hpp"
#include <iostream>
#include <thread>

namespace RawrXD {

Deep2InferenceService& Deep2InferenceService::instance() {
    static Deep2InferenceService service;
    return service;
}

bool Deep2InferenceService::initialize(const Deep2::EngineConfig& config) {
    std::lock_guard<std::mutex> lock(initMutex_);

    if (engineInitialized_) {
        return true;
    }

    std::cout << "[Deep2InferenceService] Initializing shared Deep2 engine..." << std::endl;

    if (!engine_.initialize(config)) {
        std::cerr << "[Deep2InferenceService] Failed to initialize Deep2 engine" << std::endl;
        return false;
    }

    engineInitialized_ = true;
    std::cout << "[Deep2InferenceService] Shared Deep2 engine initialized" << std::endl;
    return true;
}

bool Deep2InferenceService::loadModel(const std::string& ggufPath) {
    std::lock_guard<std::mutex> lock(initMutex_);

    if (!engineInitialized_) {
        std::cerr << "[Deep2InferenceService] Engine not initialized" << std::endl;
        return false;
    }

    // If same model already loaded, skip
    if (modelLoaded_.load() && modelPath_ == ggufPath) {
        return true;
    }

    // If different model loaded, unload first
    if (modelLoaded_.load() && modelPath_ != ggufPath) {
        engine_.unloadModel();
        modelLoaded_ = false;
        modelPath_.clear();
    }

    std::cout << "[Deep2InferenceService] Loading model: " << ggufPath << std::endl;

    if (!engine_.loadModel(ggufPath)) {
        std::cerr << "[Deep2InferenceService] Failed to load model: " << ggufPath << std::endl;
        return false;
    }

    modelLoaded_ = true;
    modelPath_ = ggufPath;
    std::cout << "[Deep2InferenceService] Model loaded successfully: " << ggufPath << std::endl;
    return true;
}

std::string Deep2InferenceService::generateText(const std::string& prompt, size_t maxTokens) {
    // Serialize all generation calls on the shared engine
    std::lock_guard<std::mutex> lock(generationMutex_);

    if (!engineInitialized_.load()) {
        std::cerr << "[Deep2InferenceService] Engine not initialized" << std::endl;
        return "";
    }

    if (!modelLoaded_.load()) {
        std::cerr << "[Deep2InferenceService] No model loaded" << std::endl;
        return "";
    }

    if (prompt.empty()) {
        return "";
    }

    clearCancellation();
    generationActive_ = true;

    std::string result;
    try {
        result = engine_.generateText(prompt, maxTokens);
    } catch (const std::exception& e) {
        std::cerr << "[Deep2InferenceService] Generation error: " << e.what() << std::endl;
    }

    generationActive_ = false;

    if (cancellationRequested()) {
        std::cerr << "[Deep2InferenceService] Generation was cancelled" << std::endl;
        return "";
    }

    if (result.empty()) {
        std::cerr << "[Deep2InferenceService] Model returned empty response" << std::endl;
        return "";
    }

    return result;
}

void Deep2InferenceService::requestCancellation() {
    cancelGeneration_ = true;
}

bool Deep2InferenceService::cancellationRequested() const {
    return cancelGeneration_.load();
}

void Deep2InferenceService::clearCancellation() {
    cancelGeneration_ = false;
}

void Deep2InferenceService::configureGeneration(const Deep2::GenerationOptions& options) {
    if (!engineInitialized_.load()) {
        std::cerr << "[Deep2InferenceService] Engine not initialized" << std::endl;
        return;
    }

    engine_.configureGeneration(options);
}

void Deep2InferenceService::shutdown() {
    std::lock_guard<std::mutex> lock(initMutex_);

    // Wait for any in-progress generation to complete before unloading
    while (generationActive_.load()) {
        std::this_thread::yield();
    }

    if (modelLoaded_.load()) {
        engine_.unloadModel();
        modelLoaded_ = false;
        modelPath_.clear();
    }

    engineInitialized_ = false;
    std::cout << "[Deep2InferenceService] Shared Deep2 engine shut down" << std::endl;
}

} // namespace RawrXD
