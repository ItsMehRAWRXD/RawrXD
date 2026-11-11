#pragma once

#include "model_registry.hpp"
#include "model_router.hpp"
#include <thread>
#include <atomic>
#include <queue>

namespace rawrxd::serving {

// Multi-model serving configuration
struct MultiModelConfig {
    size_t max_loaded_models = 10;
    size_t max_memory_gb = 80;
    size_t min_memory_per_model_gb = 4;
    int max_concurrent_loads = 2;
    float load_timeout_seconds = 300.0f;
    bool enable_auto_scaling = true;
    bool enable_preloading = true;
    std::string eviction_policy = "lru";  // lru, lfu, random
};

// Load request
struct LoadRequest {
    std::string model_full_name;
    std::string model_path;
    int gpu_device_id = -1;
    bool blocking = false;
    std::promise<bool> completion_promise;
    std::chrono::steady_clock::time_point submitted_at;
};

// Multi-model manager
class MultiModelManager {
public:
    explicit MultiModelManager(const MultiModelConfig& config);
    ~MultiModelManager();

    // Initialize
    bool initialize(std::shared_ptr<ModelRegistry> registry);

    // Start/stop manager
    void start();
    void stop();

    // Load/unload models
    bool loadModel(const std::string& full_name, 
                   const std::string& path,
                   int gpu_device_id = -1,
                   bool blocking = true);
    bool loadModelAsync(const std::string& full_name,
                        const std::string& path,
                        int gpu_device_id = -1);
    bool unloadModel(const std::string& full_name);
    bool unloadModelAsync(const std::string& full_name);

    // Preload models (warmup)
    bool preloadModel(const std::string& full_name);
    void setPreloadList(const std::vector<std::string>& model_names);

    // Get model for inference
    std::optional<std::shared_ptr<Model>> getModel(const std::string& full_name);
    std::optional<std::shared_ptr<Model>> getModel(const RoutingDecision& decision);

    // Check if model is loaded
    bool isLoaded(const std::string& full_name) const;
    bool isLoading(const std::string& full_name) const;

    // Resource management
    size_t getAvailableMemory() const;
    size_t getUsedMemory() const;
    float getMemoryUtilization() const;

    // Auto-scaling
    void setAutoScaling(bool enabled) { config_.enable_auto_scaling = enabled; }
    void scaleModel(const std::string& full_name, int num_instances);

    // Statistics
    struct Stats {
        uint64_t models_loaded = 0;
        uint64_t models_unloaded = 0;
        uint64_t load_failures = 0;
        size_t current_loaded_models = 0;
        size_t current_instances = 0;
        float avg_load_time_seconds = 0.0f;
    };
    Stats getStats() const { return stats_; }

private:
    MultiModelConfig config_;
    std::shared_ptr<ModelRegistry> registry_;
    
    std::atomic<bool> running_{false};
    std::thread load_thread_;
    std::thread unload_thread_;
    
    std::queue<LoadRequest> load_queue_;
    std::queue<std::string> unload_queue_;
    mutable std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    std::atomic<size_t> current_loads_{0};
    std::atomic<size_t> used_memory_bytes_{0};
    
    Stats stats_;
    mutable std::mutex stats_mutex_;
    
    // Background threads
    void loadLoop();
    void unloadLoop();
    
    // Model loading
    bool doLoadModel(const LoadRequest& request);
    bool canLoadModel(size_t required_memory) const;
    void evictIfNeeded(size_t required_memory);
    
    // Eviction policies
    std::string selectEvictionCandidate();
    std::string selectLRU();
    std::string selectLFU();
    std::string selectRandom();
};

// Model pool (for multi-instance serving)
class ModelPool {
public:
    explicit ModelPool(const std::string& model_full_name);

    // Add/remove instances
    void addInstance(const ModelInstance& instance);
    void removeInstance(const std::string& instance_id);
    
    // Get instance for request
    std::optional<ModelInstance> acquireInstance();
    void releaseInstance(const std::string& instance_id);
    
    // Health management
    void markUnhealthy(const std::string& instance_id);
    void markHealthy(const std::string& instance_id);
    
    // Stats
    size_t getHealthyCount() const;
    size_t getUnhealthyCount() const;
    size_t getBusyCount() const;

private:
    std::string model_full_name_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, ModelInstance> instances_;
    std::unordered_set<std::string> busy_instances_;
    std::unordered_set<std::string> unhealthy_instances_;
};

// Resource allocator
class ResourceAllocator {
public:
    struct ResourceRequest {
        size_t memory_bytes;
        int gpu_count;
        std::vector<int> preferred_gpus;
    };
    
    struct Allocation {
        bool granted = false;
        size_t memory_bytes = 0;
        int gpu_device_id = -1;
        std::string rejection_reason;
    };
    
    Allocation requestResources(const ResourceRequest& request);
    void releaseResources(const Allocation& allocation);
    
    // GPU management
    void registerGPU(int device_id, size_t memory_bytes);
    void unregisterGPU(int device_id);
    std::vector<int> getAvailableGPUs() const;
    size_t getAvailableMemory(int gpu_device_id) const;

private:
    struct GPUInfo {
        int device_id;
        size_t total_memory;
        size_t used_memory = 0;
        bool available = true;
    };
    mutable std::mutex mutex_;
    std::unordered_map<int, GPUInfo> gpus_;
};

// Model lifecycle hooks
class ModelLifecycleHooks {
public:
    using PreLoadHook = std::function<bool(const std::string& model_name)>;
    using PostLoadHook = std::function<void(const std::string& model_name, bool success)>;
    using PreUnloadHook = std::function<bool(const std::string& model_name)>;
    using PostUnloadHook = std::function<void(const std::string& model_name)>;
    
    void registerPreLoad(PreLoadHook hook);
    void registerPostLoad(PostLoadHook hook);
    void registerPreUnload(PreUnloadHook hook);
    void registerPostUnload(PostUnloadHook hook);
    
    bool runPreLoad(const std::string& model_name);
    void runPostLoad(const std::string& model_name, bool success);
    bool runPreUnload(const std::string& model_name);
    void runPostUnload(const std::string& model_name);

private:
    std::vector<PreLoadHook> pre_load_hooks_;
    std::vector<PostLoadHook> post_load_hooks_;
    std::vector<PreUnloadHook> pre_unload_hooks_;
    std::vector<PostUnloadHook> post_unload_hooks_;
    mutable std::mutex mutex_;
};

} // namespace rawrxd::serving
