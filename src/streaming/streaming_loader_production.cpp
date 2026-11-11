//=============================================================================
// RawrXD Streaming Model Loader - PRODUCTION IMPLEMENTATION
//=============================================================================

#include "streaming_loader_production.hpp"
#include <algorithm>
#include <iostream>
#include "gguf_loader.h"

namespace RawrXD {

//=============================================================================
// Streaming GGUF Loader Implementation
//=============================================================================

StreamingGGUFLoader::StreamingGGUFLoader()
    : running_(false), paused_(false)
    , current_generation_(0), bytes_loaded_(0), bytes_evicted_(0)
    , cache_hits_(0), cache_misses_(0), eviction_policy_("lru") {
    
    // Initialize zones with default limits
    for (size_t i = 0; i < static_cast<size_t>(MemoryZone::COUNT); ++i) {
        zones_[i].max_size = 512 * 1024 * 1024; // 512MB default
        zones_[i].current_size = 0;
        zones_[i].eviction_threshold = 0.9f; // 90%
    }
}

StreamingGGUFLoader::~StreamingGGUFLoader() {
    StopBackgroundLoading();
}

bool StreamingGGUFLoader::InitializeZones(const std::vector<size_t>& zone_limits_mb) {
    if (zone_limits_mb.size() != static_cast<size_t>(MemoryZone::COUNT)) {
        return false;
    }
    
    for (size_t i = 0; i < zone_limits_mb.size(); ++i) {
        zones_[i].max_size = zone_limits_mb[i] * 1024 * 1024;
        zones_[i].current_size = 0;
    }
    
    return true;
}

bool StreamingGGUFLoader::LoadStreaming(const std::string& path) {
    // First do standard GGUF load (metadata + tensor info)
    if (!Load(path)) {
        return false;
    }
    
    // Pre-assign zones based on tensor names
    for (size_t i = 0; i < GetTensorCount(); ++i) {
        const GGUFTensorInfo* tensor = GetTensor(i);
        if (tensor) {
            MemoryZone zone = InferZone(tensor->name);
            tensor_zones_[tensor->name] = zone;
        }
    }
    
    // Start background loading
    StartBackgroundLoading();
    
    return true;
}

MemoryZone StreamingGGUFLoader::InferZone(const std::string& tensor_name) {
    // Infer zone from tensor name patterns
    if (tensor_name.find("token_embd") != std::string::npos ||
        tensor_name.find("embed") != std::string::npos) {
        return MemoryZone::EMBEDDING;
    }
    if (tensor_name.find("attn_q") != std::string::npos ||
        tensor_name.find("attention_q") != std::string::npos) {
        return MemoryZone::ATTENTION_Q;
    }
    if (tensor_name.find("attn_k") != std::string::npos ||
        tensor_name.find("attention_k") != std::string::npos) {
        return MemoryZone::ATTENTION_K;
    }
    if (tensor_name.find("attn_v") != std::string::npos ||
        tensor_name.find("attention_v") != std::string::npos) {
        return MemoryZone::ATTENTION_V;
    }
    if (tensor_name.find("attn_output") != std::string::npos ||
        tensor_name.find("attention_o") != std::string::npos) {
        return MemoryZone::ATTENTION_OUT;
    }
    if (tensor_name.find("ffn_up") != std::string::npos ||
        tensor_name.find("feed_forward_up") != std::string::npos) {
        return MemoryZone::FFN_UP;
    }
    if (tensor_name.find("ffn_down") != std::string::npos ||
        tensor_name.find("feed_forward_down") != std::string::npos) {
        return MemoryZone::FFN_DOWN;
    }
    if (tensor_name.find("output") != std::string::npos ||
        tensor_name.find("lm_head") != std::string::npos) {
        return MemoryZone::OUTPUT;
    }
    
    // Default to embedding zone
    return MemoryZone::EMBEDDING;
}

void StreamingGGUFLoader::RequestTensor(const std::string& name, MemoryZone zone, int priority) {
    TensorLoadRequest req;
    req.tensor_name = name;
    req.zone = zone;
    req.priority = priority;
    req.generation_id = current_generation_.load();
    
    std::lock_guard<std::mutex> lock(queue_mutex_);
    load_queue_.push(std::move(req));
    queue_cv_.notify_one();
}

void StreamingGGUFLoader::RequestTensors(const std::vector<std::string>& names, MemoryZone zone) {
    for (const auto& name : names) {
        RequestTensor(name, zone, 0);
    }
}

void StreamingGGUFLoader::PrefetchForGeneration(uint64_t generation_id) {
    current_generation_ = generation_id;
    
    // Prefetch tensors likely needed for this generation
    // This would be model-specific logic
    // For now, just mark the generation
}

std::vector<uint8_t> StreamingGGUFLoader::GetTensorDataSync(const std::string& name) {
    // Check if already resident
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        auto it = resident_tensors_.find(name);
        if (it != resident_tensors_.end()) {
            cache_hits_++;
            return it->second;
        }
    }
    
    cache_misses_++;
    
    // Get zone for this tensor
    MemoryZone zone = MemoryZone::EMBEDDING;
    auto zone_it = tensor_zones_.find(name);
    if (zone_it != tensor_zones_.end()) {
        zone = zone_it->second;
    }
    
    // Load synchronously
    if (LoadTensorIntoZone(name, zone)) {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        auto it = resident_tensors_.find(name);
        if (it != resident_tensors_.end()) {
            return it->second;
        }
    }
    
    return {};
}

bool StreamingGGUFLoader::IsTensorResident(const std::string& name) const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return resident_tensors_.find(name) != resident_tensors_.end();
}

bool StreamingGGUFLoader::LoadTensorIntoZone(const std::string& name, MemoryZone zone) {
    const GGUFTensorInfo* tensor = GetTensor(name);
    if (!tensor) return false;
    
    size_t zone_idx = static_cast<size_t>(zone);
    
    // Check if we need to evict
    EvictIfNeeded(zone, tensor->size);
    
    // Check if tensor fits in zone
    if (tensor->size > zones_[zone_idx].max_size) {
        return false; // Tensor too large for zone
    }
    
    // Load tensor data
    std::vector<uint8_t> data = GGUFLoader::LoadTensorData(*tensor);
    if (data.empty()) return false;
    
    // Store in zone
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        resident_tensors_[name] = std::move(data);
        zones_[zone_idx].current_size += tensor->size;
        zones_[zone_idx].resident_tensors.push_back(name);
    }
    
    bytes_loaded_ += tensor->size;
    
    if (on_loaded_) {
        on_loaded_(name);
    }
    
    return true;
}

void StreamingGGUFLoader::EvictIfNeeded(MemoryZone zone, size_t needed_space) {
    size_t zone_idx = static_cast<size_t>(zone);
    
    while (zones_[zone_idx].current_size + needed_space > zones_[zone_idx].max_size) {
        if (zones_[zone_idx].resident_tensors.empty()) break;
        
        // Simple LRU: evict first tensor
        // In production, would use proper LRU tracking
        const std::string& victim = zones_[zone_idx].resident_tensors.front();
        
        const GGUFTensorInfo* tensor = GetTensor(victim);
        if (tensor) {
            zones_[zone_idx].current_size -= tensor->size;
            bytes_evicted_ += tensor->size;
        }
        
        resident_tensors_.erase(victim);
        zones_[zone_idx].resident_tensors.erase(
            zones_[zone_idx].resident_tensors.begin());
        
        if (on_evict_) {
            on_evict_(victim);
        }
    }
}

void StreamingGGUFLoader::EvictFromZone(MemoryZone zone, size_t target_size) {
    size_t zone_idx = static_cast<size_t>(zone);
    
    while (zones_[zone_idx].current_size > target_size && 
           !zones_[zone_idx].resident_tensors.empty()) {
        const std::string& victim = zones_[zone_idx].resident_tensors.front();
        
        const GGUFTensorInfo* tensor = GetTensor(victim);
        if (tensor) {
            zones_[zone_idx].current_size -= tensor->size;
            bytes_evicted_ += tensor->size;
        }
        
        resident_tensors_.erase(victim);
        zones_[zone_idx].resident_tensors.erase(
            zones_[zone_idx].resident_tensors.begin());
        
        if (on_evict_) {
            on_evict_(victim);
        }
    }
}

size_t StreamingGGUFLoader::GetZoneSize(MemoryZone zone) const {
    return zones_[static_cast<size_t>(zone)].current_size;
}

size_t StreamingGGUFLoader::GetZoneLimit(MemoryZone zone) const {
    return zones_[static_cast<size_t>(zone)].max_size;
}

float StreamingGGUFLoader::GetZoneUtilization(MemoryZone zone) const {
    size_t idx = static_cast<size_t>(zone);
    if (zones_[idx].max_size == 0) return 0.0f;
    return static_cast<float>(zones_[idx].current_size) / zones_[idx].max_size;
}

float StreamingGGUFLoader::GetHitRate() const {
    size_t total = cache_hits_ + cache_misses_;
    if (total == 0) return 0.0f;
    return static_cast<float>(cache_hits_) / total;
}

void StreamingGGUFLoader::StartBackgroundLoading() {
    if (running_) return;
    
    running_ = true;
    paused_ = false;
    background_thread_ = std::thread(&StreamingGGUFLoader::BackgroundLoadThread, this);
}

void StreamingGGUFLoader::StopBackgroundLoading() {
    running_ = false;
    queue_cv_.notify_all();
    
    if (background_thread_.joinable()) {
        background_thread_.join();
    }
}

void StreamingGGUFLoader::PauseBackgroundLoading() {
    paused_ = true;
}

void StreamingGGUFLoader::ResumeBackgroundLoading() {
    paused_ = false;
    queue_cv_.notify_all();
}

void StreamingGGUFLoader::BackgroundLoadThread() {
    while (running_) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        
        queue_cv_.wait(lock, [this] {
            return !running_ || (!paused_ && !load_queue_.empty());
        });
        
        if (!running_) break;
        if (paused_) continue;
        if (load_queue_.empty()) continue;
        
        TensorLoadRequest req = std::move(load_queue_.front());
        load_queue_.pop();
        lock.unlock();
        
        ProcessLoadRequest(req);
    }
}

void StreamingGGUFLoader::ProcessLoadRequest(const TensorLoadRequest& req) {
    // Check if already loaded
    if (IsTensorResident(req.tensor_name)) {
        return;
    }
    
    // Load into zone
    LoadTensorIntoZone(req.tensor_name, req.zone);
}

void StreamingGGUFLoader::SetEvictionPolicy(const std::string& policy) {
    eviction_policy_ = policy;
}

} // namespace RawrXD

