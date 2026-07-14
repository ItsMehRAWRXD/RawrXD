// ============================================================================
// RAWRXD FINAL UNIFIED SYSTEM - PART 2
// Streaming Loader, Capability System, Policy Router, Inference Engine
// ============================================================================

#include "RawrXD_Final_Unified.hpp"
#include <cstring>
#include <algorithm>
#include <numeric>
#include <random>
#include <iomanip>
#include <sstream>
#include <chrono>

namespace RawrXD {

// ============================================================================
// STREAMING MODEL LOADER IMPLEMENTATION
// ============================================================================

StreamingModelLoader::StreamingModelLoader() = default;

StreamingModelLoader::~StreamingModelLoader() {
    if (streaming_active_) {
        CancelStreamLoad();
    }
}

bool StreamingModelLoader::BeginStreamLoad(const std::string& filepath, const LoadConfig& config) {
    if (streaming_active_) {
        return false;
    }
    
    config_ = config;
    loader_ = std::make_shared<ZeroDependencyGGUFLoader>();
    
    if (!loader_->Open(filepath)) {
        return false;
    }
    
    if (!loader_->ParseHeader() || !loader_->ParseMetadata() || !loader_->ParseTensorInfo()) {
        return false;
    }
    
    streaming_active_ = true;
    cancel_requested_ = false;
    current_tensor_idx_ = 0;
    start_time_ = std::chrono::steady_clock::now();
    
    // Initialize default zone
    MemoryZone default_zone;
    default_zone.id = 0;
    default_zone.max_size = config_.max_memory_mb * 1024 * 1024;
    default_zone.current_size = 0;
    zones_[0] = std::move(default_zone);
    
    return true;
}

bool StreamingModelLoader::StreamNextChunk(std::function<void(const LoadProgress&)> callback) {
    if (!streaming_active_ || cancel_requested_) {
        return false;
    }
    
    auto& tensors = loader_->GetTensors();
    if (current_tensor_idx_ >= tensors.size()) {
        streaming_active_ = false;
        return true;
    }
    
    // Calculate chunk size
    size_t chunk_size = CalculateOptimalChunkSize();
    size_t end_idx = std::min(current_tensor_idx_ + chunk_size, tensors.size());
    
    // Load chunk
    for (size_t i = current_tensor_idx_; i < end_idx && !cancel_requested_; ++i) {
        auto& info = const_cast<TensorInfo&>(tensors[i]);
        if (!info.loaded) {
            if (!loader_->LoadTensorData(info.name, info.hostData)) {
                return false;
            }
            info.loaded = true;
            info.data = info.hostData.data();
            
            // Assign to default zone
            std::lock_guard<std::mutex> lock(mutex_);
            zones_[0].tensors.push_back(info.name);
            zones_[0].current_size += info.size_bytes;
        }
    }
    
    // Update progress
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_);
    
    LoadProgress progress;
    progress.bytes_loaded = 0;
    progress.bytes_total = 0;
    for (const auto& tensor : tensors) {
        progress.bytes_total += tensor.size_bytes;
        if (tensor.loaded) {
            progress.bytes_loaded += tensor.size_bytes;
        }
    }
    progress.tensors_loaded = end_idx;
    progress.tensors_total = tensors.size();
    progress.percentage = static_cast<float>(progress.tensors_loaded) / progress.tensors_total * 100.0f;
    progress.current_tensor = tensors[end_idx - 1].name;
    progress.elapsed_ms = elapsed;
    
    if (callback) {
        callback(progress);
    }
    
    current_tensor_idx_ = end_idx;
    
    if (current_tensor_idx_ >= tensors.size()) {
        streaming_active_ = false;
    }
    
    return true;
}

bool StreamingModelLoader::IsStreamingComplete() const {
    return !streaming_active_;
}

void StreamingModelLoader::CancelStreamLoad() {
    cancel_requested_ = true;
    streaming_active_ = false;
}

bool StreamingModelLoader::AssignTensorToZone(const std::string& tensor_name, uint32_t zone_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto tensor = loader_->GetTensor(tensor_name);
    if (!tensor) return false;
    
    auto zone_it = zones_.find(zone_id);
    if (zone_it == zones_.end()) {
        // Create new zone
        MemoryZone new_zone;
        new_zone.id = zone_id;
        new_zone.max_size = config_.max_memory_mb * 1024 * 1024 / 4;  // Quarter of total
        new_zone.current_size = 0;
        zones_[zone_id] = std::move(new_zone);
        zone_it = zones_.find(zone_id);
    }
    
    auto& zone = zone_it->second;
    if (zone.current_size + tensor->size_bytes > zone.max_size) {
        return false;  // Zone full
    }
    
    // Remove from old zone
    for (auto& [id, z] : zones_) {
        auto it = std::find(z.tensors.begin(), z.tensors.end(), tensor_name);
        if (it != z.tensors.end()) {
            z.tensors.erase(it);
            z.current_size -= tensor->size_bytes;
            break;
        }
    }
    
    // Add to new zone
    zone.tensors.push_back(tensor_name);
    zone.current_size += tensor->size_bytes;
    
    return true;
}

bool StreamingModelLoader::EvictZone(uint32_t zone_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = zones_.find(zone_id);
    if (it == zones_.end()) return false;
    
    auto& zone = it->second;
    if (zone.locked) return false;
    
    // Unload all tensors in zone
    for (const auto& tensor_name : zone.tensors) {
        auto tensor = loader_->GetTensor(tensor_name);
        if (tensor && tensor->loaded) {
            const_cast<TensorInfo*>(tensor)->hostData.clear();
            const_cast<TensorInfo*>(tensor)->hostData.shrink_to_fit();
            const_cast<TensorInfo*>(tensor)->loaded = false;
            const_cast<TensorInfo*>(tensor)->data = nullptr;
        }
    }
    
    zone.current_size = 0;
    zone.tensors.clear();
    
    return true;
}

bool StreamingModelLoader::PinTensor(const std::string& tensor_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    pinned_tensors_.insert(tensor_name);
    return true;
}

bool StreamingModelLoader::UnpinTensor(const std::string& tensor_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    pinned_tensors_.erase(tensor_name);
    return true;
}

size_t StreamingModelLoader::GetMemoryUsage() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t total = 0;
    for (const auto& [id, zone] : zones_) {
        total += zone.current_size;
    }
    return total;
}

size_t StreamingModelLoader::GetPinnedMemory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t total = 0;
    for (const auto& name : pinned_tensors_) {
        auto tensor = loader_->GetTensor(name);
        if (tensor) {
            total += tensor->size_bytes;
        }
    }
    return total;
}

std::vector<std::string> StreamingModelLoader::GetLoadedTensors() const {
    std::vector<std::string> result;
    for (const auto& tensor : loader_->GetTensors()) {
        if (tensor.loaded) {
            result.push_back(tensor.name);
        }
    }
    return result;
}

size_t StreamingModelLoader::CalculateOptimalChunkSize() const {
    // Calculate based on memory constraints and tensor sizes
    size_t avg_tensor_size = 0;
    const auto& tensors = loader_->GetTensors();
    if (!tensors.empty()) {
        size_t total = 0;
        for (const auto& t : tensors) {
            total += t.size_bytes;
        }
        avg_tensor_size = total / tensors.size();
    }
    
    size_t chunk_bytes = config_.chunk_size_mb * 1024 * 1024;
    if (avg_tensor_size > 0) {
        return std::max(size_t(1), chunk_bytes / avg_tensor_size);
    }
    return 10;  // Default: 10 tensors per chunk
}

// ============================================================================
// CAPABILITY TOKEN SYSTEM IMPLEMENTATION
// ============================================================================

ExecutionCapability::ExecutionCapability(CapabilityType type, uint64_t nonce)
    : type_(type), nonce_(nonce), valid_(type != CapabilityType::INVALID), expired_(false) {}

ExecutionCapability::ExecutionCapability(ExecutionCapability&& other) noexcept
    : type_(other.type_), nonce_(other.nonce_), valid_(other.valid_), expired_(other.expired_) {
    other.valid_ = false;
    other.expired_ = true;
}

ExecutionCapability& ExecutionCapability::operator=(ExecutionCapability&& other) noexcept {
    if (this != &other) {
        type_ = other.type_;
        nonce_ = other.nonce_;
        valid_ = other.valid_;
        expired_ = other.expired_;
        other.valid_ = false;
        other.expired_ = true;
    }
    return *this;
}

std::string ExecutionCapability::ToString() const {
    std::stringstream ss;
    ss << "Capability[";
    switch (type_) {
        case CapabilityType::INVALID: ss << "INVALID"; break;
        case CapabilityType::LOCAL_GGUF: ss << "LOCAL_GGUF"; break;
        case CapabilityType::LOCAL_OLLAMA: ss << "LOCAL_OLLAMA"; break;
        case CapabilityType::REMOTE_CLOUD: ss << "REMOTE_CLOUD"; break;
        case CapabilityType::HYBRID: ss << "HYBRID"; break;
    }
    ss << ", nonce=" << std::hex << nonce_ << ", valid=" << (IsValid() ? "yes" : "no") << "]";
    return ss.str();
}

TokenAuthority& TokenAuthority::Instance() {
    static TokenAuthority instance;
    return instance;
}

ExecutionCapability TokenAuthority::MintCapability(CapabilityType type, const std::string& requester) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;
    
    uint64_t nonce;
    do {
        nonce = dis(gen);
    } while (revoked_nonces_.count(nonce) > 0);
    
    mint_count_++;
    return ExecutionCapability(type, nonce);
}

bool TokenAuthority::RevokeCapability(uint64_t nonce) {
    std::lock_guard<std::mutex> lock(mutex_);
    return revoked_nonces_.insert(nonce).second;
}

bool TokenAuthority::IsRevoked(uint64_t nonce) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return revoked_nonces_.count(nonce) > 0;
}

size_t TokenAuthority::GetMintCount() const {
    return mint_count_.load();
}

void TokenAuthority::ClearRevoked() {
    std::lock_guard<std::mutex> lock(mutex_);
    revoked_nonces_.clear();
}

// ============================================================================
// POLICY ROUTER IMPLEMENTATION
// ============================================================================

PolicyRouter::PolicyRouter(ExecutionMode default_mode) : default_mode_(default_mode) {}

PolicyRouter::RoutingDecision PolicyRouter::DecideExecutionPath(const ModelConfig& config,
                                                               bool local_available,
                                                               bool remote_available) {
    RoutingDecision decision;
    decision.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    ExecutionMode mode = config.execution_mode;
    
    switch (mode) {
        case ExecutionMode::STRICT_LOCAL:
            decision.capability_type = CapabilityType::LOCAL_GGUF;
            decision.reason = "StrictLocal: local only";
            decision.confidence = 1.0f;
            break;
            
        case ExecutionMode::HYBRID_CONTROLLED:
            if (local_available) {
                decision.capability_type = CapabilityType::LOCAL_GGUF;
                decision.reason = "HybridControlled: local preferred";
                decision.confidence = 0.95f;
            } else if (remote_available) {
                decision.capability_type = CapabilityType::REMOTE_CLOUD;
                decision.reason = "HybridControlled: cloud fallback";
                decision.confidence = 0.85f;
            } else {
                decision.capability_type = CapabilityType::LOCAL_GGUF;
                decision.reason = "HybridControlled: local only (no cloud)";
                decision.confidence = 0.7f;
            }
            break;
            
        case ExecutionMode::FULLY_DISTRIBUTED:
            if (local_available && remote_available) {
                decision.capability_type = CapabilityType::HYBRID;
                decision.reason = "FullyDistributed: automatic routing";
                decision.confidence = 0.9f;
            } else if (local_available) {
                decision.capability_type = CapabilityType::LOCAL_GGUF;
                decision.reason = "FullyDistributed: local only";
                decision.confidence = 0.8f;
            } else {
                decision.capability_type = CapabilityType::REMOTE_CLOUD;
                decision.reason = "FullyDistributed: cloud only";
                decision.confidence = 0.8f;
            }
            break;
    }
    
    RecordDecision(decision);
    return decision;
}

std::vector<PolicyRouter::RoutingDecision> PolicyRouter::GetRecentDecisions(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t start = recent_decisions_.size() > count ? recent_decisions_.size() - count : 0;
    return std::vector<RoutingDecision>(recent_decisions_.begin() + start, recent_decisions_.end());
}

void PolicyRouter::RecordDecision(const RoutingDecision& decision) {
    std::lock_guard<std::mutex> lock(mutex_);
    recent_decisions_.push_back(decision);
    decision_count_++;
    
    // Keep only last 1000 decisions
    if (recent_decisions_.size() > 1000) {
        recent_decisions_.erase(recent_decisions_.begin());
    }
}

// ============================================================================
// INFERENCE ENGINE IMPLEMENTATION
// ============================================================================

InferenceEngine::InferenceEngine() = default;

InferenceEngine::~InferenceEngine() {
    Shutdown();
}

bool InferenceEngine::Initialize(const ModelConfig& config) {
    if (initialized_) {
        return false;
    }
    
    config_ = config;
    
    // Initialize loader
    loader_ = std::make_shared<ZeroDependencyGGUFLoader>();
    streamer_ = std::make_shared<StreamingModelLoader>();
    
    initialized_ = true;
    return true;
}

void InferenceEngine::Shutdown() {
    if (!initialized_) return;
    
    UnloadModel();
    loader_.reset();
    streamer_.reset();
    initialized_ = false;
}

bool InferenceEngine::LoadModel(const std::string& path) {
    if (!initialized_) return false;
    if (model_loaded_) {
        UnloadModel();
    }
    
    // Open and parse
    if (!loader_->Open(path)) {
        return false;
    }
    
    if (!loader_->ParseHeader() || !loader_->ParseMetadata() || !loader_->ParseTensorInfo()) {
        loader_->Close();
        return false;
    }
    
    // Validate architecture
    if (!loader_->IsSupportedArchitecture()) {
        loader_->Close();
        return false;
    }
    
    // Stream load tensors
    StreamingModelLoader::LoadConfig stream_config;
    stream_config.max_memory_mb = config_.batch_size * 16;  // Estimate
    
    if (!streamer_->BeginStreamLoad(path, stream_config)) {
        loader_->Close();
        return false;
    }
    
    // Load all tensors
    while (!streamer_->IsStreamingComplete()) {
        if (!streamer_->StreamNextChunk(nullptr)) {
            return false;
        }
    }
    
    model_loaded_ = true;
    return true;
}

void InferenceEngine::UnloadModel() {
    if (loader_) {
        loader_->Close();
    }
    model_loaded_ = false;
}

InferenceResponse InferenceEngine::Generate(const InferenceRequest& request) {
    InferenceResponse response;
    
    if (!model_loaded_) {
        response.success = false;
        response.error = "No model loaded";
        return response;
    }
    
    auto start_time = std::chrono::steady_clock::now();
    
    // Tokenize input
    auto tokens = Tokenize(request.prompt);
    response.prompt_tokens = static_cast<uint32_t>(tokens.size());
    
    // Execute based on mode
    if (request.mode == ExecutionMode::STRICT_LOCAL || !request.allow_remote) {
        response = ExecuteLocal(request);
    } else {
        // For now, always execute locally
        response = ExecuteLocal(request);
    }
    
    auto end_time = std::chrono::steady_clock::now();
    response.latency_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    
    UpdateStats(response);
    return response;
}

bool InferenceEngine::GenerateStreaming(const InferenceRequest& request) {
    // For now, just generate and call callback with chunks
    auto response = Generate(request);
    
    if (response.success && request.stream_callback) {
        // Simulate streaming by breaking response into chunks
        size_t chunk_size = 10;
        for (size_t i = 0; i < response.text.length(); i += chunk_size) {
            std::string chunk = response.text.substr(i, chunk_size);
            request.stream_callback(chunk);
        }
    }
    
    return response.success;
}

InferenceResponse InferenceEngine::ExecuteLocal(const InferenceRequest& request) {
    InferenceResponse response;
    response.arch_type = loader_->DetectArchitecture();
    response.execution_path = "local";
    
    // Simulate inference
    auto tokens = Tokenize(request.prompt);
    
    // Generate response based on architecture
    std::string arch_name = loader_->GetArchitectureName();
    response.text = "[Generated by " + arch_name + "] Response to: " + request.prompt.substr(0, 50);
    if (request.prompt.length() > 50) {
        response.text += "...";
    }
    
    response.tokens_generated = static_cast<uint32_t>(response.text.length() / 4);  // Rough estimate
    response.success = true;
    
    return response;
}

InferenceResponse InferenceEngine::ExecuteRemote(const InferenceRequest& request) {
    InferenceResponse response;
    response.execution_path = "remote";
    response.error = "Remote execution not implemented";
    response.success = false;
    return response;
}

std::vector<int32_t> InferenceEngine::Tokenize(const std::string& text) {
    // Simple character-level tokenization for now
    std::vector<int32_t> tokens;
    for (char c : text) {
        tokens.push_back(static_cast<int32_t>(c));
    }
    return tokens;
}

std::string InferenceEngine::Detokenize(const std::vector<int32_t>& tokens) {
    std::string text;
    for (int32_t token : tokens) {
        if (token >= 0 && token < 256) {
            text += static_cast<char>(token);
        }
    }
    return text;
}

void InferenceEngine::UpdateStats(const InferenceResponse& response) {
    stats_.total_requests++;
    if (response.success) {
        stats_.successful_requests++;
        stats_.total_tokens_generated += response.tokens_generated;
    } else {
        stats_.failed_requests++;
    }
    
    // Update averages
    double alpha = 0.1;  // Exponential moving average
    stats_.avg_latency_ms = (1.0 - alpha) * stats_.avg_latency_ms + alpha * response.latency_ms;
    
    if (response.latency_ms > 0) {
        double tps = response.tokens_generated * 1000.0 / response.latency_ms;
        stats_.avg_tokens_per_second = (1.0 - alpha) * stats_.avg_tokens_per_second + alpha * tps;
    }
}

void InferenceEngine::ResetStats() {
    stats_ = EngineStats{};
}

} // namespace RawrXD
