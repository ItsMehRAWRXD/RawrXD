// Phase D.14 Batch 1/5: Edge Deployment
// Deploy and manage models on edge devices
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace Edge {

// Forward declarations
struct EdgeDevice;
struct EdgeDeployment;

// ============================================================================
// Edge Types
// ============================================================================

enum class DeviceStatus {
    OFFLINE = 0,
    ONLINE = 1,
    BUSY = 2,
    ERROR = 3,
    UPDATING = 4
};

enum class DeploymentStatus {
    PENDING = 0,
    DEPLOYING = 1,
    ACTIVE = 2,
    FAILED = 3,
    ROLLING_BACK = 4,
    ROLLED_BACK = 5
};

enum class DeviceType {
    IOT_SENSOR = 0,
    EDGE_GATEWAY = 1,
    MOBILE_DEVICE = 2,
    INDUSTRIAL_CONTROLLER = 3,
    AUTONOMOUS_VEHICLE = 4,
    SMART_CAMERA = 5,
    ROBOTICS_UNIT = 6
};

struct DeviceCapabilities {
    std::string cpu_arch;           // x86_64, arm64, armv7
    int cpu_cores = 0;
    int ram_mb = 0;
    int storage_mb = 0;
    bool has_gpu = false;
    std::string gpu_type;
    bool has_npu = false;
    std::string npu_type;
    std::vector<std::string> supported_frameworks;
    std::vector<std::string> supported_formats;
    double max_power_watts = 0.0;
    double network_bandwidth_mbps = 0.0;
};

struct EdgeDevice {
    std::string device_id;
    std::string name;
    DeviceType type;
    DeviceStatus status;
    DeviceCapabilities capabilities;
    std::string location;
    std::string firmware_version;
    std::chrono::steady_clock::time_point last_seen;
    std::chrono::steady_clock::time_point registered_at;
    std::map<std::string, std::string> tags;
    std::map<std::string, std::any> metadata;
};

struct EdgeDeployment {
    std::string deployment_id;
    std::string device_id;
    std::string model_name;
    std::string model_version;
    DeploymentStatus status;
    std::string model_path;
    std::map<std::string, std::any> config;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point deployed_at;
    std::chrono::steady_clock::time_point updated_at;
    double memory_usage_mb = 0.0;
    double cpu_usage_percent = 0.0;
    int inference_count = 0;
    double avg_latency_ms = 0.0;
};

// ============================================================================
// Edge Deployment Manager
// ============================================================================

class EdgeDeploymentManager {
public:
    struct Config {
        std::string deployment_server_url;
        std::string artifact_store_path;
        int max_concurrent_deployments = 10;
        std::chrono::seconds deployment_timeout{300};
        bool enable_rollback = true;
    };
    
    explicit EdgeDeploymentManager(const Config& config);
    ~EdgeDeploymentManager();
    
    bool Initialize();
    void Shutdown();
    
    // Deployment lifecycle
    std::string CreateDeployment(const std::string& device_id,
                                  const std::string& model_name,
                                  const std::string& model_version,
                                  const std::map<std::string, std::any>& config = {});
    bool StartDeployment(const std::string& deployment_id);
    bool CancelDeployment(const std::string& deployment_id);
    bool RollbackDeployment(const std::string& deployment_id);
    bool DeleteDeployment(const std::string& deployment_id);
    
    // Deployment queries
    EdgeDeployment GetDeployment(const std::string& deployment_id) const;
    std::vector<EdgeDeployment> GetDeployments(const std::string& device_id = "") const;
    std::vector<EdgeDeployment> GetDeploymentsByStatus(DeploymentStatus status) const;
    
    // Deployment status
    bool UpdateDeploymentStatus(const std::string& deployment_id, 
                                DeploymentStatus status);
    bool UpdateDeploymentMetrics(const std::string& deployment_id,
                                  double memory_mb,
                                  double cpu_percent,
                                  int inference_count,
                                  double avg_latency_ms);
    
private:
    Config config_;
    std::map<std::string, EdgeDeployment> deployments_;
    mutable std::mutex deployments_mutex_;
};

// ============================================================================
// Edge Device Registry
// ============================================================================

class EdgeDeviceRegistry {
public:
    struct Config {
        std::string registry_backend = "redis";  // redis, etcd, consul
        std::map<std::string, std::string> backend_config;
        std::chrono::seconds heartbeat_timeout{60};
        bool auto_unregister_offline = true;
    };
    
    explicit EdgeDeviceRegistry(const Config& config);
    ~EdgeDeviceRegistry();
    
    bool Initialize();
    void Shutdown();
    
    // Device registration
    std::string RegisterDevice(const std::string& name,
                                DeviceType type,
                                const DeviceCapabilities& capabilities,
                                const std::string& location = "");
    bool UnregisterDevice(const std::string& device_id);
    bool UpdateDevice(const std::string& device_id, 
                      const EdgeDevice& device);
    
    // Device queries
    EdgeDevice GetDevice(const std::string& device_id) const;
    std::vector<EdgeDevice> GetAllDevices() const;
    std::vector<EdgeDevice> GetDevicesByType(DeviceType type) const;
    std::vector<EdgeDevice> GetDevicesByStatus(DeviceStatus status) const;
    std::vector<EdgeDevice> GetDevicesByLocation(const std::string& location) const;
    std::vector<EdgeDevice> GetDevicesByTag(const std::string& key, 
                                             const std::string& value) const;
    
    // Device status
    bool UpdateDeviceStatus(const std::string& device_id, DeviceStatus status);
    bool UpdateDeviceHeartbeat(const std::string& device_id);
    bool UpdateDeviceFirmware(const std::string& device_id, 
                               const std::string& version);
    
    // Device capabilities matching
    std::vector<EdgeDevice> FindCompatibleDevices(
        const DeviceCapabilities& requirements) const;
    bool CheckCompatibility(const std::string& device_id,
                            const DeviceCapabilities& requirements) const;
    
private:
    Config config_;
    std::map<std::string, EdgeDevice> devices_;
    mutable std::mutex devices_mutex_;
    std::thread heartbeat_thread_;
    std::atomic<bool> running_{false};
    
    void HeartbeatMonitorLoop();
    void CleanupOfflineDevices();
};

// ============================================================================
// Edge Model Optimizer
// ============================================================================

class EdgeModelOptimizer {
public:
    struct OptimizationConfig {
        std::string target_device;
        int target_latency_ms = 100;
        int max_memory_mb = 512;
        double min_accuracy = 0.95;
        std::vector<std::string> optimizations = {
            "quantization", "pruning", "distillation", "compilation"
        };
    };
    
    struct OptimizationResult {
        std::string optimized_model_path;
        std::string format;  // tflite, onnx, tensorrt, coreml
        int original_size_mb = 0;
        int optimized_size_mb = 0;
        double compression_ratio = 0.0;
        double accuracy_delta = 0.0;
        double measured_latency_ms = 0.0;
        double measured_memory_mb = 0.0;
        std::map<std::string, std::any> metadata;
    };
    
    explicit EdgeModelOptimizer();
    
    // Optimization methods
    OptimizationResult QuantizeModel(const std::string& model_path,
                                        const std::string& target_format,
                                        int bits = 8);
    OptimizationResult PruneModel(const std::string& model_path,
                                     float sparsity = 0.5f);
    OptimizationResult DistillModel(const std::string& teacher_path,
                                     const std::string& student_architecture,
                                     const std::string& dataset_path);
    OptimizationResult CompileModel(const std::string& model_path,
                                       const std::string& target_backend);
    
    // Full optimization pipeline
    OptimizationResult OptimizeForEdge(const std::string& model_path,
                                        const OptimizationConfig& config);
    
    // Benchmark
    struct BenchmarkResult {
        double latency_ms = 0.0;
        double throughput_fps = 0.0;
        double memory_mb = 0.0;
        double power_watts = 0.0;
    };
    BenchmarkResult BenchmarkModel(const std::string& model_path,
                                    const DeviceCapabilities& device);
    
private:
    std::map<std::string, std::function<OptimizationResult(const std::string&)>> 
        optimizers_;
};

// ============================================================================
// Edge Sync Service
// ============================================================================

class EdgeSyncService {
public:
    struct Config {
        std::string sync_mode = "delta";  // full, delta, adaptive
        std::chrono::seconds sync_interval{300};
        int max_bandwidth_kbps = 1000;
        bool compress_transfers = true;
        bool encrypt_transfers = true;
    };
    
    struct SyncJob {
        std::string job_id;
        std::string device_id;
        std::string source_path;
        std::string target_path;
        std::string sync_type;  // model, data, config
        std::chrono::steady_clock::time_point scheduled_at;
        std::chrono::steady_clock::time_point completed_at;
        bool success = false;
        std::string error_message;
        int bytes_transferred = 0;
    };
    
    explicit EdgeSyncService(const Config& config);
    ~EdgeSyncService();
    
    bool Initialize();
    void Shutdown();
    
    // Sync operations
    std::string ScheduleSync(const std::string& device_id,
                              const std::string& source_path,
                              const std::string& target_path,
                              const std::string& sync_type);
    bool CancelSync(const std::string& job_id);
    
    // Sync queries
    SyncJob GetSyncJob(const std::string& job_id) const;
    std::vector<SyncJob> GetSyncJobs(const std::string& device_id = "") const;
    std::vector<SyncJob> GetPendingSyncs() const;
    
    // Delta sync
    std::string ComputeDelta(const std::string& old_model_path,
                              const std::string& new_model_path);
    bool ApplyDelta(const std::string& base_model_path,
                    const std::string& delta_path,
                    const std::string& output_path);
    
private:
    Config config_;
    std::map<std::string, SyncJob> sync_jobs_;
    mutable std::mutex jobs_mutex_;
    std::thread sync_thread_;
    std::atomic<bool> running_{false};
    
    void SyncLoop();
    bool ExecuteSync(SyncJob& job);
};

// ============================================================================
// Edge Deployment Runtime
// ============================================================================

class EdgeDeploymentRuntime {
public:
    struct Config {
        EdgeDeploymentManager::Config deployment;
        EdgeDeviceRegistry::Config registry;
        EdgeSyncService::Config sync;
    };
    
    explicit EdgeDeploymentRuntime(const Config& config);
    ~EdgeDeploymentRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    EdgeDeploymentManager* GetDeploymentManager();
    EdgeDeviceRegistry* GetDeviceRegistry();
    EdgeModelOptimizer* GetModelOptimizer();
    EdgeSyncService* GetSyncService();
    
    // High-level operations
    std::string DeployToEdge(const std::string& device_id,
                              const std::string& model_name,
                              const std::string& model_version,
                              const EdgeModelOptimizer::OptimizationConfig& opt_config = {});
    
    bool UpdateEdgeModel(const std::string& deployment_id,
                         const std::string& new_version);
    
    std::vector<EdgeDevice> GetHealthyDevices() const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<EdgeDeploymentManager> deployment_manager_;
    std::unique_ptr<EdgeDeviceRegistry> device_registry_;
    std::unique_ptr<EdgeModelOptimizer> model_optimizer_;
    std::unique_ptr<EdgeSyncService> sync_service_;
};

} // namespace Edge
} // namespace Sovereign
