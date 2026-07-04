// ============================================================================
// agentic_model_streamer_bridge.cpp
// ============================================================================
// Implementation of AgenticModelStreamerBridge
// Connects AgenticEngine with StreamingGGUFLoader for unified model management
//
// Copyright (c) 2025-2026 RawrXD Project
// ============================================================================

#include "agentic_model_streamer_bridge.h"
#include <iostream>
#include <algorithm>
#include <sstream>
#include <chrono>

namespace RawrXD {
namespace Agentic {

// Global singleton instance
static AgenticModelStreamerBridge* g_globalBridge = nullptr;

AgenticModelStreamerBridge* GetGlobalAgenticModelStreamer() {
    return g_globalBridge;
}

void SetGlobalAgenticModelStreamer(AgenticModelStreamerBridge* bridge) {
    g_globalBridge = bridge;
}

// ============================================================================
// AgenticModelStreamerBridge Implementation
// ============================================================================

AgenticModelStreamerBridge::AgenticModelStreamerBridge() 
    : m_streamingLoader(std::make_unique<StreamingGGUFLoader>()) {
}

AgenticModelStreamerBridge::~AgenticModelStreamerBridge() {
    Shutdown();
}

bool AgenticModelStreamerBridge::Initialize(AgenticEngine* engine) {
    if (m_initialized) {
        return true;
    }

    if (!engine) {
        std::cerr << "[AgenticModelStreamer] ERROR: No agentic engine provided" << std::endl;
        return false;
    }

    m_agenticEngine = engine;
    
    // Create and set up the streaming inference engine
    auto streamingEngine = std::make_shared<StreamingModelInferenceEngine>(this);
    SetInferenceEngine(streamingEngine);
    m_agenticEngine->setInferenceEngine(streamingEngine.get());

    // Start the background loading thread
    m_shutdown = false;
    m_loadingThread = std::thread(&AgenticModelStreamerBridge::LoadingThreadFunc, this);

    m_initialized = true;
    SetGlobalAgenticModelStreamer(this);
    
    std::cerr << "[AgenticModelStreamer] Initialized successfully" << std::endl;
    return true;
}

void AgenticModelStreamerBridge::Shutdown() {
    if (!m_initialized) {
        return;
    }

    m_shutdown = true;
    m_queueCV.notify_all();

    if (m_loadingThread.joinable()) {
        m_loadingThread.join();
    }

    UnloadModel();
    
    m_initialized = false;
    if (g_globalBridge == this) {
        SetGlobalAgenticModelStreamer(nullptr);
    }
    
    std::cerr << "[AgenticModelStreamer] Shutdown complete" << std::endl;
}

// ============================================================================
// Model Loading API
// ============================================================================

std::string AgenticModelStreamerBridge::QueueModelLoad(const ModelLoadRequest& request) {
    std::string taskId = "model_load_" + std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());
    
    ModelLoadRequest req = request;
    req.taskId = taskId;
    req.requestTime = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lk(m_queueMutex);
        m_loadQueue.push(req);
    }
    
    m_queueCV.notify_one();
    
    std::cerr << "[AgenticModelStreamer] Queued model load: " << taskId 
              << " for " << request.modelPath << std::endl;
    
    return taskId;
}

bool AgenticModelStreamerBridge::LoadModelSync(const std::string& modelPath, uint64_t maxMemoryMB) {
    ModelLoadRequest request;
    request.modelPath = modelPath;
    request.maxMemoryMB = maxMemoryMB;
    request.enableStreaming = true;
    request.preloadZones = false;
    
    std::atomic<bool> completed(false);
    std::atomic<bool> success(false);
    std::string error;
    
    request.callback = [&completed, &success, &error](bool s, const std::string& e) {
        success = s;
        error = e;
        completed = true;
    };
    
    QueueModelLoad(request);
    
    // Wait for completion
    while (!completed) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    if (!success) {
        std::cerr << "[AgenticModelStreamer] Model load failed: " << error << std::endl;
    }
    
    return success;
}

void AgenticModelStreamerBridge::UnloadModel() {
    std::lock_guard<std::mutex> lk(m_modelMutex);
    
    if (m_streamingLoader) {
        m_streamingLoader->Close();
    }
    
    m_currentModelPath.clear();
    m_currentMetadata = GGUFMetadata{};
    
    {
        std::lock_guard<std::mutex> statusLk(m_statusMutex);
        m_status.isLoaded = false;
        m_status.isLoading = false;
        m_status.loadedZones.clear();
        m_status.memoryUsedMB = 0;
    }
    
    NotifyStatusUpdate();
    
    std::cerr << "[AgenticModelStreamer] Model unloaded" << std::endl;
}

bool AgenticModelStreamerBridge::IsModelLoaded() const {
    std::lock_guard<std::mutex> lk(m_statusMutex);
    return m_status.isLoaded;
}

std::string AgenticModelStreamerBridge::GetCurrentModelPath() const {
    std::lock_guard<std::mutex> lk(m_modelMutex);
    return m_currentModelPath;
}

GGUFMetadata AgenticModelStreamerBridge::GetCurrentModelMetadata() const {
    std::lock_guard<std::mutex> lk(m_modelMutex);
    return m_currentMetadata;
}

// ============================================================================
// Zone Management
// ============================================================================

bool AgenticModelStreamerBridge::LoadZone(const std::string& zoneName, uint64_t maxMemoryMB) {
    if (!m_streamingLoader) {
        return false;
    }
    
    bool success = m_streamingLoader->LoadZone(zoneName, maxMemoryMB);
    
    if (success) {
        std::lock_guard<std::mutex> lk(m_statusMutex);
        if (std::find(m_status.loadedZones.begin(), m_status.loadedZones.end(), zoneName) 
            == m_status.loadedZones.end()) {
            m_status.loadedZones.push_back(zoneName);
        }
        m_status.memoryUsedMB = GetCurrentMemoryUsageMB();
        NotifyStatusUpdate();
    }
    
    return success;
}

bool AgenticModelStreamerBridge::UnloadZone(const std::string& zoneName) {
    if (!m_streamingLoader) {
        return false;
    }
    
    bool success = m_streamingLoader->UnloadZone(zoneName);
    
    if (success) {
        std::lock_guard<std::mutex> lk(m_statusMutex);
        auto it = std::find(m_status.loadedZones.begin(), m_status.loadedZones.end(), zoneName);
        if (it != m_status.loadedZones.end()) {
            m_status.loadedZones.erase(it);
        }
        m_status.memoryUsedMB = GetCurrentMemoryUsageMB();
        NotifyStatusUpdate();
    }
    
    return success;
}

bool AgenticModelStreamerBridge::IsZoneLoaded(const std::string& zoneName) const {
    std::lock_guard<std::mutex> lk(m_statusMutex);
    return std::find(m_status.loadedZones.begin(), m_status.loadedZones.end(), zoneName) 
           != m_status.loadedZones.end();
}

std::vector<std::string> AgenticModelStreamerBridge::GetLoadedZones() const {
    std::lock_guard<std::mutex> lk(m_statusMutex);
    return m_status.loadedZones;
}

void AgenticModelStreamerBridge::PreloadZonesForInference(const std::vector<std::string>& zoneNames) {
    for (const auto& zone : zoneNames) {
        if (!IsZoneLoaded(zone)) {
            LoadZone(zone, 512); // 512MB default per zone
        }
    }
}

// ============================================================================
// Status & Monitoring
// ============================================================================

ModelStreamerStatus AgenticModelStreamerBridge::GetStatus() const {
    std::lock_guard<std::mutex> lk(m_statusMutex);
    return m_status;
}

void AgenticModelStreamerBridge::SetStatusCallback(std::function<void(const ModelStreamerStatus&)> callback) {
    m_statusCallback = callback;
}

// ============================================================================
// Agentic Integration
// ============================================================================

std::shared_ptr<InferenceEngine> AgenticModelStreamerBridge::GetInferenceEngine() {
    return m_inferenceEngine;
}

void AgenticModelStreamerBridge::SetInferenceEngine(std::shared_ptr<InferenceEngine> engine) {
    m_inferenceEngine = engine;
}

std::string AgenticModelStreamerBridge::ExecuteAgenticTask(const std::string& task, const std::string& context) {
    if (!m_agenticEngine) {
        return "Error: Agentic engine not initialized";
    }
    
    // Check if model is loaded
    if (!IsModelLoaded()) {
        return "Error: No model loaded. Please load a model first.";
    }
    
    // Execute the task through the agentic engine
    std::string fullContext = "Task: " + task + "\nContext: " + context;
    return m_agenticEngine->chat(fullContext);
}

// ============================================================================
// Memory Management
// ============================================================================

void AgenticModelStreamerBridge::SetMemoryBudget(uint64_t maxMemoryMB) {
    m_memoryBudgetMB = maxMemoryMB;
    std::cerr << "[AgenticModelStreamer] Memory budget set to " << maxMemoryMB << " MB" << std::endl;
}

uint64_t AgenticModelStreamerBridge::GetCurrentMemoryUsageMB() const {
    if (!m_streamingLoader) {
        return 0;
    }
    return m_streamingLoader->GetCurrentMemoryUsage() / (1024 * 1024);
}

void AgenticModelStreamerBridge::EmergencyMemoryCleanup() {
    std::cerr << "[AgenticModelStreamer] Emergency memory cleanup initiated" << std::endl;
    
    // Unload all zones except essential ones
    auto zones = GetLoadedZones();
    for (const auto& zone : zones) {
        if (zone != "embedding" && zone != "output") { // Keep essential zones
            UnloadZone(zone);
        }
    }
    
    if (m_inferenceEngine) {
        m_inferenceEngine->ClearCache();
    }
}

// ============================================================================
// Internal Implementation
// ============================================================================

void AgenticModelStreamerBridge::LoadingThreadFunc() {
    std::cerr << "[AgenticModelStreamer] Loading thread started" << std::endl;
    
    while (!m_shutdown) {
        ModelLoadRequest request;
        bool hasRequest = false;
        
        {
            std::unique_lock<std::mutex> lk(m_queueMutex);
            m_queueCV.wait(lk, [this] { return !m_loadQueue.empty() || m_shutdown; });
            
            if (m_shutdown) break;
            
            if (!m_loadQueue.empty()) {
                request = m_loadQueue.front();
                m_loadQueue.pop();
                hasRequest = true;
            }
        }
        
        if (hasRequest) {
            bool success = ProcessLoadRequest(request);
            if (request.callback) {
                request.callback(success, success ? "" : m_status.lastError);
            }
        }
    }
    
    std::cerr << "[AgenticModelStreamer] Loading thread stopped" << std::endl;
}

bool AgenticModelStreamerBridge::ProcessLoadRequest(const ModelLoadRequest& request) {
    std::cerr << "[AgenticModelStreamer] Processing load request: " << request.modelPath << std::endl;
    
    // Update status
    {
        std::lock_guard<std::mutex> lk(m_statusMutex);
        m_status.isLoading = true;
        m_status.isLoaded = false;
        m_status.currentModelPath = request.modelPath;
        m_status.currentOperation = "parsing_header";
        m_status.progressPercent = 0.0f;
        m_status.memoryBudgetMB = request.maxMemoryMB;
    }
    NotifyStatusUpdate();
    
    // Unload any existing model
    UnloadModel();
    
    // Open the model file
    if (!m_streamingLoader->Open(request.modelPath)) {
        std::lock_guard<std::mutex> lk(m_statusMutex);
        m_status.isLoading = false;
        m_status.lastError = "Failed to open model file: " + request.modelPath;
        NotifyStatusUpdate();
        return false;
    }
    
    UpdateProgress("loading_metadata", 25.0f);
    
    // Get metadata
    m_currentMetadata = m_streamingLoader->GetMetadata();
    m_currentModelPath = request.modelPath;
    
    UpdateProgress("building_index", 50.0f);
    
    // Preload zones if requested
    if (request.preloadZones && !request.requiredZones.empty()) {
        UpdateProgress("loading_zones", 75.0f);
        PreloadZonesForInference(request.requiredZones);
    }
    
    UpdateProgress("ready", 100.0f);
    
    // Update final status
    {
        std::lock_guard<std::mutex> lk(m_statusMutex);
        m_status.isLoading = false;
        m_status.isLoaded = true;
        m_status.currentOperation = "ready";
        m_status.progressPercent = 100.0f;
        m_status.memoryUsedMB = GetCurrentMemoryUsageMB();
        m_status.totalBytes = m_streamingLoader->GetTotalFileSize();
    }
    NotifyStatusUpdate();
    
    std::cerr << "[AgenticModelStreamer] Model loaded successfully: " << request.modelPath << std::endl;
    std::cerr << "[AgenticModelStreamer]   Layers: " << m_currentMetadata.layer_count << std::endl;
    std::cerr << "[AgenticModelStreamer]   Context: " << m_currentMetadata.context_length << std::endl;
    std::cerr << "[AgenticModelStreamer]   Embedding: " << m_currentMetadata.embedding_dim << std::endl;
    std::cerr << "[AgenticModelStreamer]   Vocab: " << m_currentMetadata.vocab_size << std::endl;
    
    return true;
}

void AgenticModelStreamerBridge::UpdateProgress(const std::string& operation, float percent) {
    {
        std::lock_guard<std::mutex> lk(m_statusMutex);
        m_status.currentOperation = operation;
        m_status.progressPercent = percent;
    }
    NotifyStatusUpdate();
}

void AgenticModelStreamerBridge::NotifyStatusUpdate() {
    if (m_statusCallback) {
        ModelStreamerStatus status;
        {
            std::lock_guard<std::mutex> lk(m_statusMutex);
            status = m_status;
        }
        m_statusCallback(status);
    }
}

// ============================================================================
// StreamingModelInferenceEngine Implementation
// ============================================================================

StreamingModelInferenceEngine::StreamingModelInferenceEngine(AgenticModelStreamerBridge* bridge)
    : m_bridge(bridge) {
}

StreamingModelInferenceEngine::~StreamingModelInferenceEngine() {
}

bool StreamingModelInferenceEngine::LoadModel(const std::string& model_path) {
    if (!m_bridge) {
        return false;
    }
    bool success = m_bridge->LoadModelSync(model_path);
    m_modelLoaded = success;
    return success;
}

bool StreamingModelInferenceEngine::IsModelLoaded() const {
    return m_modelLoaded && m_bridge && m_bridge->IsModelLoaded();
}

std::vector<int32_t> StreamingModelInferenceEngine::Tokenize(const std::string& text) {
    if (!m_bridge || text.empty()) return {};
    
    // Simple character-level tokenization as fallback
    // Map each unique character to an ID
    std::vector<int32_t> tokens;
    tokens.reserve(text.length());
    
    // Simple approach: use ASCII value for basic chars, hash for others
    for (char c : text) {
        if (static_cast<unsigned char>(c) < 128) {
            tokens.push_back(static_cast<int32_t>(c));
        } else {
            // For non-ASCII, use a hash-based approach
            tokens.push_back(128 + (static_cast<unsigned char>(c) % 100));
        }
    }
    
    return tokens;
}

std::string StreamingModelInferenceEngine::Detokenize(const std::vector<int32_t>& tokens) {
    if (tokens.empty()) return "";
    
    // Simple character-level detokenization
    std::string result;
    result.reserve(tokens.size());
    
    for (int32_t token : tokens) {
        if (token >= 0 && token < 128) {
            result += static_cast<char>(token);
        } else if (token >= 128 && token < 256) {
            // Extended ASCII range - use placeholder
            result += '?';
        }
    }
    
    return result;
}

std::vector<int32_t> StreamingModelInferenceEngine::Generate(const std::vector<int32_t>& input_tokens, int max_tokens) {
    if (!m_bridge || input_tokens.empty() || max_tokens <= 0) return {};
    
    std::vector<int32_t> output;
    output.reserve(max_tokens);
    
    // Simple generation: echo pattern with increment
    int32_t last_token = input_tokens.empty() ? 0 : input_tokens.back();
    for (int i = 0; i < max_tokens; ++i) {
        // Simple pattern-based generation (placeholder for real model inference)
        int32_t next_token = (last_token + i + 1) % GetVocabSize();
        if (next_token == 0) break; // EOS
        output.push_back(next_token);
        last_token = next_token;
    }
    
    return output;
}

std::vector<float> StreamingModelInferenceEngine::Eval(const std::vector<int32_t>& input_tokens) {
    if (!m_bridge || input_tokens.empty()) return {};
    
    // Return dummy logits for each token
    int vocab_size = GetVocabSize();
    if (vocab_size <= 0) vocab_size = 32000;
    
    std::vector<float> logits(vocab_size, 0.0f);
    // Set some dummy probabilities
    for (size_t i = 0; i < input_tokens.size() && i < static_cast<size_t>(vocab_size); ++i) {
        if (input_tokens[i] >= 0 && input_tokens[i] < vocab_size) {
            logits[input_tokens[i]] = 1.0f / (i + 1);
        }
    }
    return logits;
}

void StreamingModelInferenceEngine::GenerateStreaming(
    const std::vector<int32_t>& input_tokens,
    int max_tokens,
    std::function<void(const std::string&)> token_callback,
    std::function<void()> complete_callback,
    std::function<void(int32_t)> token_id_callback) {
    
    if (!m_bridge || !token_callback) {
        if (complete_callback) complete_callback();
        return;
    }
    
    // Generate tokens and stream them
    auto tokens = Generate(input_tokens, max_tokens);
    
    for (int32_t token_id : tokens) {
        if (token_id_callback) {
            token_id_callback(token_id);
        }
        
        // Convert token to string (simplified)
        std::string token_str = std::to_string(token_id) + " ";
        token_callback(token_str);
        
        // Small delay to simulate streaming
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    if (complete_callback) {
        complete_callback();
    }
}

int StreamingModelInferenceEngine::GetVocabSize() const {
    if (!m_bridge) return 0;
    auto metadata = m_bridge->GetCurrentModelMetadata();
    return static_cast<int>(metadata.vocab_size);
}

int StreamingModelInferenceEngine::GetEmbeddingDim() const {
    if (!m_bridge) return 0;
    auto metadata = m_bridge->GetCurrentModelMetadata();
    return static_cast<int>(metadata.embedding_dim);
}

int StreamingModelInferenceEngine::GetNumLayers() const {
    if (!m_bridge) return 0;
    auto metadata = m_bridge->GetCurrentModelMetadata();
    return static_cast<int>(metadata.layer_count);
}

int StreamingModelInferenceEngine::GetNumHeads() const {
    // TODO: Get from metadata when available
    return 0;
}

void StreamingModelInferenceEngine::SetMaxMode(bool enabled) {
    m_maxMode = enabled;
}

void StreamingModelInferenceEngine::SetDeepThinking(bool enabled) {
    m_deepThinking = enabled;
}

void StreamingModelInferenceEngine::SetDeepResearch(bool enabled) {
    m_deepResearch = enabled;
}

bool StreamingModelInferenceEngine::IsMaxMode() const {
    return m_maxMode;
}

bool StreamingModelInferenceEngine::IsDeepThinking() const {
    return m_deepThinking;
}

bool StreamingModelInferenceEngine::IsDeepResearch() const {
    return m_deepResearch;
}

size_t StreamingModelInferenceEngine::GetMemoryUsage() const {
    if (!m_bridge) return 0;
    return m_bridge->GetCurrentMemoryUsageMB() * 1024 * 1024;
}

void StreamingModelInferenceEngine::ClearCache() {
    if (m_bridge) {
        m_bridge->EmergencyMemoryCleanup();
    }
}

bool StreamingModelInferenceEngine::EnsureZonesLoaded(const std::vector<std::string>& zoneNames) {
    if (!m_bridge) return false;
    return true; // Placeholder - zones are loaded on demand
}

void StreamingModelInferenceEngine::SetZoneCachePolicy(const std::string& policy) {
    m_cachePolicy = policy;
}

} // namespace Agentic
} // namespace RawrXD
