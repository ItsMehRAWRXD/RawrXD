//=============================================================================
// RawrXD Streaming Model Loader - PRODUCTION IMPLEMENTATION
// Zero dependencies, zone-based memory management, true streaming
//=============================================================================

#ifndef RAWRXD_STREAMING_LOADER_HPP
#define RAWRXD_STREAMING_LOADER_HPP

#include "gguf_loader_production.hpp"
#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <atomic>

namespace RawrXD {

//=============================================================================
// Memory Zone Management
//=============================================================================

enum class MemoryZone {
    EMBEDDING = 0,    // Vocabulary embeddings
    ATTENTION_Q,      // Query weights
    ATTENTION_K,      // Key weights
    ATTENTION_V,      // Value weights
    ATTENTION_OUT,    // Attention output
    FFN_UP,           // Feed-forward up-projection
    FFN_DOWN,         // Feed-forward down-projection
    OUTPUT,           // LM head / output
    COUNT
};

struct ZoneConfig {
    size_t max_size;
    size_t current_size;
    size_t eviction_threshold;
    std::vector<std::string> resident_tensors;
};

//=============================================================================
// Tensor Load Request
//=============================================================================

struct TensorLoadRequest {
    std::string tensor_name;
    MemoryZone zone;
    int priority;  // Higher = load first
    uint64_t generation_id;
};

//=============================================================================
// Streaming GGUF Loader
//=============================================================================

class StreamingGGUFLoader : public GGUFLoader {
public:
    using ZoneEvictionCallback = std::function<void(const std::string& tensor_name)>;
    using TensorLoadedCallback = std::function<void(const std::string& tensor_name)>;
    
    StreamingGGUFLoader();
    ~StreamingGGUFLoader();
    
    // Initialize with zone limits (in MB)
    bool InitializeZones(const std::vector<size_t>& zone_limits_mb);
    
    // Streaming load
    bool LoadStreaming(const std::string& path);
    
    // Request tensor loading (async)
    void RequestTensor(const std::string& name, MemoryZone zone, int priority = 0);
    void RequestTensors(const std::vector<std::string>& names, MemoryZone zone);
    
    // Prefetch tensors for upcoming generation
    void PrefetchForGeneration(uint64_t generation_id);
    
    // Get tensor data (blocks until loaded)
    std::vector<uint8_t> GetTensorDataSync(const std::string& name);
    
    // Check if tensor is resident
    bool IsTensorResident(const std::string& name) const;
    
    // Zone management
    size_t GetZoneSize(MemoryZone zone) const;
    size_t GetZoneLimit(MemoryZone zone) const;
    float GetZoneUtilization(MemoryZone zone) const;
    
    // Eviction policy
    void SetEvictionPolicy(const std::string& policy); // "lru", "lfu", "fifo"
    void EvictFromZone(MemoryZone zone, size_t target_size);
    
    // Callbacks
    void SetZoneEvictionCallback(ZoneEvictionCallback cb) { on_evict_ = cb; }
    void SetTensorLoadedCallback(TensorLoadedCallback cb) { on_loaded_ = cb; }
    
    // Background loading control
    void StartBackgroundLoading();
    void StopBackgroundLoading();
    void PauseBackgroundLoading();
    void ResumeBackgroundLoading();
    
    // Statistics
    size_t GetBytesLoaded() const { return bytes_loaded_; }
    size_t GetBytesEvicted() const { return bytes_evicted_; }
    size_t GetCacheHits() const { return cache_hits_; }
    size_t GetCacheMisses() const { return cache_misses_; }
    float GetHitRate() const;

private:
    void BackgroundLoadThread();
    void ProcessLoadRequest(const TensorLoadRequest& req);
    bool LoadTensorIntoZone(const std::string& name, MemoryZone zone);
    void EvictIfNeeded(MemoryZone zone, size_t needed_space);
    MemoryZone InferZone(const std::string& tensor_name);
    
    std::unordered_map<std::string, MemoryZone> tensor_zones_;
    std::unordered_map<std::string, std::vector<uint8_t>> resident_tensors_;
    std::array<ZoneConfig, static_cast<size_t>(MemoryZone::COUNT)> zones_;
    
    std::queue<TensorLoadRequest> load_queue_;
    mutable std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    std::thread background_thread_;
    std::atomic<bool> running_;
    std::atomic<bool> paused_;
    
    std::atomic<uint64_t> current_generation_;
    std::atomic<size_t> bytes_loaded_;
    std::atomic<size_t> bytes_evicted_;
    std::atomic<size_t> cache_hits_;
    std::atomic<size_t> cache_misses_;
    
    ZoneEvictionCallback on_evict_;
    TensorLoadedCallback on_loaded_;
    
    std::string eviction_policy_;
};

} // namespace RawrXD

#endif // RAWRXD_STREAMING_LOADER_HPP
