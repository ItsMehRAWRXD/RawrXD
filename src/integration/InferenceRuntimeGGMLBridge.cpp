// ============================================================================
// InferenceRuntimeGGMLBridge.cpp
// Bridge implementation connecting distributed runtime to GGML backend
// ============================================================================
// VAL-018: Distributed Inference Pipeline
// Evidence collection for complete inference trace
//
// Copyright (c) 2026 RawrXD Team
// ============================================================================

#include "InferenceRuntimeGGMLBridge.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <filesystem>

namespace RawrXD {
namespace Integration {

// ============================================================================
// Metrics Serialization
// ============================================================================

std::string InferenceMetrics::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"request_id\": " << requestId << ",\n";
    oss << "  \"timing\": {\n";
    oss << "    \"enqueue_us\": " << enqueueTimeUs << ",\n";
    oss << "    \"dispatch_us\": " << dispatchTimeUs << ",\n";
    oss << "    \"first_token_us\": " << firstTokenTimeUs << ",\n";
    oss << "    \"completion_us\": " << completionTimeUs << "\n";
    oss << "  },\n";
    oss << "  \"counts\": {\n";
    oss << "    \"tokens_generated\": " << tokensGenerated << ",\n";
    oss << "    \"tokens_per_second\": " << tokensPerSecond << ",\n";
    oss << "    \"bytes_transferred\": " << bytesTransferred << "\n";
    oss << "  },\n";
    oss << "  \"status\": {\n";
    oss << "    \"success\": " << (success ? "true" : "false") << ",\n";
    oss << "    \"error\": \"" << errorMessage << "\"\n";
    oss << "  }\n";
    oss << "}";
    return oss.str();
}

// ============================================================================
// Bridge Implementation
// ============================================================================

InferenceRuntimeGGMLBridge::InferenceRuntimeGGMLBridge(const BridgeConfig& config)
    : config_(config) {
}

InferenceRuntimeGGMLBridge::~InferenceRuntimeGGMLBridge() {
    Shutdown();
}

bool InferenceRuntimeGGMLBridge::Initialize() {
    if (running_.load()) {
        return true;
    }
    
    std::cout << "[VAL-018] Initializing InferenceRuntimeGGMLBridge..." << std::endl;
    
    // Create validation output directory
    if (!config_.validationOutputDir.empty()) {
        std::filesystem::create_directories(config_.validationOutputDir);
    }
    
    // Initialize GGML backend
    backend_ = Inference::GGMLBackend::Create(config_.ggmlConfig);
    if (!backend_) {
        std::cerr << "[VAL-018] Failed to create GGML backend" << std::endl;
        return false;
    }
    
    if (!backend_->Initialize()) {
        std::cerr << "[VAL-018] Failed to initialize GGML backend" << std::endl;
        return false;
    }
    
    std::cout << "[VAL-018] GGML backend initialized (type: " 
              << backend_->GetBackendType() << ")" << std::endl;
    
    // Load model if path provided
    if (!config_.modelPath.empty()) {
        if (!LoadModel(config_.modelPath)) {
            std::cerr << "[VAL-018] Failed to load model: " << config_.modelPath << std::endl;
            return false;
        }
    }
    
    running_ = true;
    
    // Start worker thread
    workerThread_ = std::thread(&InferenceRuntimeGGMLBridge::WorkerLoop, this);
    
    std::cout << "[VAL-018] Bridge initialized successfully" << std::endl;
    return true;
}

void InferenceRuntimeGGMLBridge::Shutdown() {
    if (!running_.load()) {
        return;
    }
    
    std::cout << "[VAL-018] Shutting down InferenceRuntimeGGMLBridge..." << std::endl;
    
    running_ = false;
    
    if (workerThread_.joinable()) {
        workerThread_.join();
    }
    
    if (backend_) {
        backend_->Shutdown();
        backend_.reset();
    }
    
    std::cout << "[VAL-018] Bridge shutdown complete" << std::endl;
}

void InferenceRuntimeGGMLBridge::AttachToRuntime(Distributed::InferenceRuntime* runtime) {
    runtime_ = runtime;
    
    if (runtime_) {
        // Set up callbacks
        runtime_->SetTokenCallback(
            [this](uint64_t reqId, uint32_t token) {
                OnTokenGenerated(reqId, token);
            });
        
        runtime_->SetCompleteCallback(
            [this](uint64_t reqId, const std::vector<uint32_t>& tokens) {
                OnRequestCompleted(reqId, tokens);
            });
        
        runtime_->SetErrorCallback(
            [this](uint64_t reqId, const std::string& error) {
                OnRequestFailed(reqId, error);
            });
    }
    
    std::cout << "[VAL-018] Attached to InferenceRuntime" << std::endl;
}

void InferenceRuntimeGGMLBridge::DetachFromRuntime() {
    if (runtime_) {
        runtime_->SetTokenCallback(nullptr);
        runtime_->SetCompleteCallback(nullptr);
        runtime_->SetErrorCallback(nullptr);
        runtime_ = nullptr;
    }
    
    std::cout << "[VAL-018] Detached from InferenceRuntime" << std::endl;
}

bool InferenceRuntimeGGMLBridge::LoadModel(const std::string& path) {
    if (!backend_) {
        std::cerr << "[VAL-018] Cannot load model: backend not initialized" << std::endl;
        return false;
    }
    
    std::cout << "[VAL-018] Loading model: " << path << std::endl;
    
    if (!backend_->LoadModel(path)) {
        std::cerr << "[VAL-018] Failed to load model" << std::endl;
        return false;
    }
    
    auto arch = backend_->GetModelArchitecture();
    std::cout << "[VAL-018] Model loaded successfully:" << std::endl;
    std::cout << "  Architecture: " << arch.name << std::endl;
    std::cout << "  Layers: " << arch.numLayers << std::endl;
    std::cout << "  Context: " << arch.contextLength << std::endl;
    std::cout << "  Vocab: " << arch.vocabSize << std::endl;
    
    return true;
}

void InferenceRuntimeGGMLBridge::UnloadModel() {
    if (backend_) {
        backend_->UnloadModel();
        std::cout << "[VAL-018] Model unloaded" << std::endl;
    }
}

bool InferenceRuntimeGGMLBridge::IsModelLoaded() const {
    return backend_ && backend_->IsModelLoaded();
}

// ============================================================================
// Request Handling
// ============================================================================

void InferenceRuntimeGGMLBridge::OnRequestSubmitted(uint64_t requestId) {
    std::cout << "[VAL-018] Request " << requestId << " submitted to bridge" << std::endl;
}

void InferenceRuntimeGGMLBridge::OnTokenGenerated(uint64_t requestId, uint32_t token) {
    // Update metrics
    std::lock_guard<std::mutex> lock(metricsMutex_);
    if (currentMetrics_.requestId == requestId) {
        currentMetrics_.tokensGenerated++;
        
        // Calculate TPS
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            now - std::chrono::steady_clock::time_point(
                std::chrono::microseconds(currentMetrics_.dispatchTimeUs))).count();
        
        if (elapsed > 0) {
            currentMetrics_.tokensPerSecond = 
                static_cast<uint32_t>((currentMetrics_.tokensGenerated * 1000000ULL) / elapsed);
        }
    }
    
    // Write token log
    WriteTokenLog(requestId, token, currentMetrics_.tokensGenerated);
}

void InferenceRuntimeGGMLBridge::OnRequestCompleted(uint64_t requestId, 
                                                      const std::vector<uint32_t>& tokens) {
    std::cout << "[VAL-018] Request " << requestId << " completed (" 
              << tokens.size() << " tokens)" << std::endl;
    
    completedRequests_++;
    
    // Finalize metrics
    {
        std::lock_guard<std::mutex> lock(metricsMutex_);
        currentMetrics_.completionTimeUs = 
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        currentMetrics_.success = true;
        currentMetrics_.tokensGenerated = static_cast<uint32_t>(tokens.size());
        
        // Calculate final TPS
        uint64_t elapsed = currentMetrics_.completionTimeUs - currentMetrics_.dispatchTimeUs;
        if (elapsed > 0) {
            currentMetrics_.tokensPerSecond = 
                static_cast<uint32_t>((tokens.size() * 1000000ULL) / elapsed);
        }
        
        metrics_.push_back(currentMetrics_);
    }
    
    // Write completion log
    WriteCompletionLog(requestId, tokens);
    
    // Export trace
    ExportTrace(std::to_string(requestId));
}

void InferenceRuntimeGGMLBridge::OnRequestFailed(uint64_t requestId, const std::string& error) {
    std::cerr << "[VAL-018] Request " << requestId << " failed: " << error << std::endl;
    
    failedRequests_++;
    
    {
        std::lock_guard<std::mutex> lock(metricsMutex_);
        currentMetrics_.completionTimeUs = 
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        currentMetrics_.success = false;
        currentMetrics_.errorMessage = error;
        metrics_.push_back(currentMetrics_);
    }
}

// ============================================================================
// Execution
// ============================================================================

void InferenceRuntimeGGMLBridge::WorkerLoop() {
    std::cout << "[VAL-018] Bridge worker thread started" << std::endl;
    
    while (running_.load()) {
        // Worker processes requests from runtime queue
        // Actual execution happens in GGML backend
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    std::cout << "[VAL-018] Bridge worker thread stopped" << std::endl;
}

// ============================================================================
// Validation Output (VAL-018 Evidence)
// ============================================================================

void InferenceRuntimeGGMLBridge::WriteRequestLog(const Distributed::InferenceRequest& request) {
    if (config_.validationOutputDir.empty()) return;
    
    std::string path = config_.validationOutputDir + "/request.json";
    std::ofstream ofs(path);
    if (!ofs) return;
    
    ofs << "{\n";
    ofs << "  \"request_id\": " << request.request_id << ",\n";
    ofs << "  \"model_id\": " << request.model_id << ",\n";
    ofs << "  \"batch_size\": " << request.batch_size << ",\n";
    ofs << "  \"seq_length\": " << request.seq_length << ",\n";
    ofs << "  \"priority\": " << request.priority << ",\n";
    ofs << "  \"timestamp\": " << request.enqueue_time.time_since_epoch().count() << "\n";
    ofs << "}";
}

void InferenceRuntimeGGMLBridge::WriteTokenLog(uint64_t requestId, uint32_t token, 
                                                  uint32_t tokenIndex) {
    if (config_.validationOutputDir.empty()) return;
    
    std::string path = config_.validationOutputDir + "/stream.log";
    std::ofstream ofs(path, std::ios::app);
    if (!ofs) return;
    
    auto now = std::chrono::steady_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
    
    ofs << "{\"request_id\":" << requestId 
        << ",\"token_index\":" << tokenIndex 
        << ",\"token\":" << token 
        << ",\"timestamp_us\":" << timestamp << "}" << std::endl;
}

void InferenceRuntimeGGMLBridge::WriteCompletionLog(uint64_t requestId, 
                                                     const std::vector<uint32_t>& tokens) {
    if (config_.validationOutputDir.empty()) return;
    
    std::string path = config_.validationOutputDir + "/completion.json";
    std::ofstream ofs(path);
    if (!ofs) return;
    
    ofs << "{\n";
    ofs << "  \"request_id\": " << requestId << ",\n";
    ofs << "  \"token_count\": " << tokens.size() << ",\n";
    ofs << "  \"tokens\": [";
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i > 0) ofs << ", ";
        ofs << tokens[i];
    }
    ofs << "],\n";
    ofs << "  \"timestamp\": " << std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count() << "\n";
    ofs << "}";
}

bool InferenceRuntimeGGMLBridge::ExportTrace(const std::string& requestId) {
    if (config_.validationOutputDir.empty()) return false;
    
    std::string path = config_.validationOutputDir + "/benchmark.json";
    std::ofstream ofs(path);
    if (!ofs) return false;
    
    std::lock_guard<std::mutex> lock(metricsMutex_);
    if (!metrics_.empty()) {
        ofs << metrics_.back().ToJson();
    }
    
    std::cout << "[VAL-018] Trace exported to: " << path << std::endl;
    return true;
}

InferenceMetrics InferenceRuntimeGGMLBridge::GetLastMetrics() const {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    if (!metrics_.empty()) {
        return metrics_.back();
    }
    return InferenceMetrics{};
}

std::vector<InferenceMetrics> InferenceRuntimeGGMLBridge::GetAllMetrics() const {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    return metrics_;
}

// ============================================================================
// Factory
// ============================================================================

std::unique_ptr<InferenceRuntimeGGMLBridge> CreateBridge(const BridgeConfig& config) {
    return std::make_unique<InferenceRuntimeGGMLBridge>(config);
}

} // namespace Integration
} // namespace RawrXD
