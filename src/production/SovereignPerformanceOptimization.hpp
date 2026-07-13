// Phase D.10 Batch 1/5: Performance Optimization & Tuning
// Production-grade performance optimization and tuning
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <thread>

namespace Sovereign {
namespace Production {

// ============================================================================
// Performance Profiler
// ============================================================================

struct ProfileSample {
    std::string function_name;
    std::string file_path;
    int line_number = 0;
    std::chrono::nanoseconds duration{0};
    std::chrono::steady_clock::time_point timestamp;
    std::thread::id thread_id;
    std::vector<std::string> call_stack;
};

struct ProfileReport {
    std::string function_name;
    std::chrono::nanoseconds total_time{0};
    std::chrono::nanoseconds avg_time{0};
    std::chrono::nanoseconds min_time{0};
    std::chrono::nanoseconds max_time{0};
    uint64_t call_count = 0;
    double percentage_of_total = 0.0;
};

class PerformanceProfiler {
public:
    struct Config {
        bool enabled = true;
        int sampling_rate = 100;  // Sample 1 in N calls
        size_t max_samples = 1000000;
        bool capture_call_stacks = false;
        int call_stack_depth = 10;
    };
    
    explicit PerformanceProfiler(const Config& config);
    ~PerformanceProfiler();
    
    bool Initialize();
    void Shutdown();
    
    // Profiling
    class ScopedProfile {
    public:
        ScopedProfile(PerformanceProfiler* profiler, const std::string& name,
                      const std::string& file, int line);
        ~ScopedProfile();
    private:
        PerformanceProfiler* profiler_;
        std::string name_;
        std::chrono::steady_clock::time_point start_;
    };
    
    void BeginProfile(const std::string& name, const std::string& file, int line);
    void EndProfile(const std::string& name);
    
    // Reports
    std::vector<ProfileReport> GenerateReport();
    std::vector<ProfileReport> GetHotspots(int top_n = 10);
    void ExportToChromeTracing(const std::string& path);
    void ExportToFlameGraph(const std::string& path);
    
    // Real-time
    std::map<std::string, double> GetCurrentMetrics();
    void OnProfileUpdate(std::function<void(const ProfileReport&)> callback);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    struct ProfileData {
        std::chrono::nanoseconds total_time{0};
        std::chrono::nanoseconds min_time{std::chrono::nanoseconds::max()};
        std::chrono::nanoseconds max_time{0};
        uint64_t call_count = 0;
    };
    
    std::map<std::string, ProfileData> profile_data_;
    std::vector<ProfileSample> samples_;
    mutable std::mutex data_mutex_;
    
    void CollectSample(const ProfileSample& sample);
};

// Performance profiling macro
#define PROFILE_SCOPE(profiler, name) \
    Sovereign::Production::PerformanceProfiler::ScopedProfile \
        _profile_##__LINE__(profiler, name, __FILE__, __LINE__)

// ============================================================================
// Memory Optimizer
// ============================================================================

struct MemoryStats {
    size_t heap_allocated = 0;
    size_t heap_used = 0;
    size_t heap_free = 0;
    size_t peak_heap_usage = 0;
    size_t allocation_count = 0;
    size_t deallocation_count = 0;
    size_t fragmentation_percent = 0;
    std::map<std::string, size_t> allocations_by_type;
};

class MemoryOptimizer {
public:
    struct Config {
        bool enable_pool_allocator = true;
        size_t small_object_size = 256;
        size_t pool_sizes[8] = {16, 32, 64, 128, 256, 512, 1024, 2048};
        bool enable_defragmentation = true;
        std::chrono::seconds defrag_interval{300};
        size_t memory_limit_mb = 8192;
        bool enable_oom_handler = true;
    };
    
    explicit MemoryOptimizer(const Config& config);
    ~MemoryOptimizer();
    
    bool Initialize();
    void Shutdown();
    
    // Allocation
    void* Allocate(size_t size);
    void Deallocate(void* ptr, size_t size);
    void* Reallocate(void* ptr, size_t old_size, size_t new_size);
    
    // Pool management
    void* AllocateFromPool(size_t size);
    void ReturnToPool(void* ptr, size_t size);
    
    // Optimization
    void RunDefragmentation();
    void CompactMemory();
    void TrimExcessMemory();
    
    // Stats
    MemoryStats GetStats() const;
    void PrintStats() const;
    std::vector<std::pair<std::string, size_t>> GetAllocationHotspots(int top_n = 10);
    
    // Tuning
    void SetMemoryLimit(size_t limit_mb);
    void SetDefragmentationInterval(std::chrono::seconds interval);
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    struct Pool {
        size_t object_size;
        std::vector<void*> free_objects;
        std::mutex mutex;
    };
    
    std::array<Pool, 8> pools_;
    MemoryStats stats_;
    mutable std::mutex stats_mutex_;
    
    std::thread defrag_thread_;
    
    void DefragLoop();
    Pool* FindPool(size_t size);
};

// ============================================================================
// CPU Optimizer
// ============================================================================

struct CPUStats {
    double usage_percent = 0.0;
    double user_percent = 0.0;
    double system_percent = 0.0;
    double io_wait_percent = 0.0;
    uint64_t context_switches = 0;
    uint64_t interrupts = 0;
    std::vector<double> core_usage;
    double thermal_throttle_percent = 0.0;
};

class CPUOptimizer {
public:
    struct Config {
        bool enable_affinity = true;
        bool enable_nice_adjustment = true;
        int io_threads = 4;
        int worker_threads = std::thread::hardware_concurrency();
        bool enable_hyperthreading = true;
        int target_cpu_percent = 80;
    };
    
    explicit CPUOptimizer(const Config& config);
    ~CPUOptimizer();
    
    bool Initialize();
    void Shutdown();
    
    // Thread management
    void SetThreadAffinity(std::thread::id tid, const std::vector<int>& cpus);
    void SetThreadPriority(std::thread::id tid, int priority);
    void PinThreadToCore(std::thread::id tid, int core);
    
    // Thread pool
    void SubmitTask(std::function<void()> task, int priority = 0);
    void SubmitIOTask(std::function<void()> task);
    void SubmitComputeTask(std::function<void()> task);
    
    // Optimization
    void BalanceLoad();
    void AdjustThreadCount();
    void OptimizeForLatency();
    void OptimizeForThroughput();
    
    // Stats
    CPUStats GetStats() const;
    std::map<std::string, double> GetThreadStats() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    struct Task {
        std::function<void()> func;
        int priority;
        std::chrono::steady_clock::time_point submitted_at;
    };
    
    std::vector<std::thread> worker_threads_;
    std::vector<std::thread> io_threads_;
    std::priority_queue<Task> task_queue_;
    std::mutex task_mutex_;
    std::condition_variable task_cv_;
    
    std::thread monitor_thread_;
    
    void WorkerLoop();
    void IOLoop();
    void MonitorLoop();
};

// ============================================================================
// Network Optimizer
// ============================================================================

struct NetworkStats {
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;
    uint64_t errors = 0;
    uint64_t dropped = 0;
    double latency_ms = 0.0;
    double throughput_mbps = 0.0;
    int active_connections = 0;
};

class NetworkOptimizer {
public:
    struct Config {
        bool enable_tcp_nodelay = true;
        bool enable_tcp_quickack = true;
        int tcp_send_buffer_size = 256 * 1024;
        int tcp_recv_buffer_size = 256 * 1024;
        bool enable_zero_copy = true;
        int max_connections_per_host = 100;
        std::chrono::seconds keepalive_interval{60};
        bool enable_connection_pooling = true;
    };
    
    explicit NetworkOptimizer(const Config& config);
    ~NetworkOptimizer();
    
    bool Initialize();
    void Shutdown();
    
    // Socket optimization
    void OptimizeSocket(int socket_fd);
    void SetSocketBufferSize(int socket_fd, int send_size, int recv_size);
    void EnableZeroCopy(int socket_fd);
    
    // Connection pooling
    int GetPooledConnection(const std::string& host, int port);
    void ReturnConnection(int socket_fd);
    void CloseIdleConnections(std::chrono::seconds max_idle);
    
    // Protocol optimization
    void EnableCompression(int socket_fd);
    void EnableMultiplexing(int socket_fd);
    
    // Stats
    NetworkStats GetStats() const;
    std::map<std::string, NetworkStats> GetStatsPerConnection() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    struct Connection {
        int socket_fd;
        std::string host;
        int port;
        std::chrono::steady_clock::time_point last_used;
        bool in_use = false;
    };
    
    std::map<std::string, std::vector<Connection>> connection_pools_;
    mutable std::mutex pools_mutex_;
    
    std::thread cleanup_thread_;
    
    void CleanupLoop();
};

// ============================================================================
// I/O Optimizer
// ============================================================================

struct IOStats {
    uint64_t bytes_read = 0;
    uint64_t bytes_written = 0;
    uint64_t read_ops = 0;
    uint64_t write_ops = 0;
    double read_latency_ms = 0.0;
    double write_latency_ms = 0.0;
    double throughput_mbps = 0.0;
    int queue_depth = 0;
};

class IOOptimizer {
public:
    struct Config {
        bool enable_aio = true;
        bool enable_io_uring = true;
        int io_queue_depth = 128;
        size_t read_ahead_size = 256 * 1024;
        bool enable_direct_io = false;
        int max_concurrent_ops = 64;
        std::chrono::milliseconds fsync_interval{1000};
    };
    
    explicit IOOptimizer(const Config& config);
    ~IOOptimizer();
    
    bool Initialize();
    void Shutdown();
    
    // Async I/O
    void ReadAsync(int fd, void* buffer, size_t size, off_t offset,
                   std::function<void(ssize_t)> callback);
    void WriteAsync(int fd, const void* buffer, size_t size, off_t offset,
                    std::function<void(ssize_t)> callback);
    void FsyncAsync(int fd, std::function<void()> callback);
    
    // Batch operations
    void SubmitBatch();
    void WaitForCompletion(int count = -1);
    
    // Optimization
    void SetReadAhead(int fd, size_t size);
    void EnableDirectIO(int fd);
    void OptimizeForRandomAccess(int fd);
    void OptimizeForSequentialAccess(int fd);
    
    // Stats
    IOStats GetStats() const;
    std::map<std::string, IOStats> GetStatsPerFile() const;
    
private:
    Config config_;
    std::atomic<bool> running_{false};
    
    struct IOOperation {
        enum Type { READ, WRITE, FSYNC } type;
        int fd;
        void* buffer;
        size_t size;
        off_t offset;
        std::function<void(ssize_t)> callback;
    };
    
    std::vector<IOOperation> pending_ops_;
    std::mutex ops_mutex_;
    
    std::thread io_thread_;
    
    void IOLoop();
    void ProcessOperation(const IOOperation& op);
};

// ============================================================================
// Cache Optimizer
// ============================================================================

template<typename Key, typename Value>
class OptimizedCache {
public:
    struct Config {
        size_t max_size = 10000;
        std::chrono::seconds ttl{300};
        bool enable_lru = true;
        bool enable_lfu = false;
        float lru_weight = 0.7f;
        float lfu_weight = 0.3f;
    };
    
    explicit OptimizedCache(const Config& config);
    
    // Operations
    bool Get(const Key& key, Value& value);
    void Put(const Key& key, const Value& value);
    void Invalidate(const Key& key);
    void InvalidateAll();
    
    // Stats
    size_t Size() const;
    double HitRate() const;
    std::map<std::string, size_t> GetStats() const;
    
    // Maintenance
    void RunEviction();
    void WarmUp(const std::vector<std::pair<Key, Value>>& data);
    
private:
    Config config_;
    
    struct CacheEntry {
        Value value;
        std::chrono::steady_clock::time_point accessed_at;
        std::chrono::steady_clock::time_point created_at;
        uint64_t access_count = 0;
        double score = 0.0;
    };
    
    std::map<Key, CacheEntry> cache_;
    mutable std::mutex cache_mutex_;
    
    uint64_t hits_ = 0;
    uint64_t misses_ = 0;
    
    double CalculateScore(const CacheEntry& entry);
    void EvictIfNeeded();
};

// ============================================================================
// Performance Runtime
// ============================================================================

class PerformanceRuntime {
public:
    struct Config {
        PerformanceProfiler::Config profiler;
        MemoryOptimizer::Config memory;
        CPUOptimizer::Config cpu;
        NetworkOptimizer::Config network;
        IOOptimizer::Config io;
    };
    
    explicit PerformanceRuntime(const Config& config);
    ~PerformanceRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    PerformanceProfiler* GetProfiler();
    MemoryOptimizer* GetMemoryOptimizer();
    CPUOptimizer* GetCPUOptimizer();
    NetworkOptimizer* GetNetworkOptimizer();
    IOOptimizer* GetIOOptimizer();
    
    // Unified optimization
    void OptimizeForWorkload(const std::string& workload_type);
    void RunFullOptimization();
    
    // Reporting
    std::map<std::string, std::any> GetPerformanceReport();
    void ExportReport(const std::string& path);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<PerformanceProfiler> profiler_;
    std::unique_ptr<MemoryOptimizer> memory_;
    std::unique_ptr<CPUOptimizer> cpu_;
    std::unique_ptr<NetworkOptimizer> network_;
    std::unique_ptr<IOOptimizer> io_;
};

} // namespace Production
} // namespace Sovereign
