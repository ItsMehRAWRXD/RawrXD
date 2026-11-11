// RawrXD Distributed Training Interface
// Phase AL: Distributed Training Support

#pragma once

#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <future>

namespace rawrxd {
namespace distributed {

// Distributed training strategies
enum class DistributedStrategy {
    DATA_PARALLEL,      // Data parallelism
    MODEL_PARALLEL,     // Model parallelism
    PIPELINE_PARALLEL,  // Pipeline parallelism
    FSDP,               // Fully Sharded Data Parallel
    DEEPSPEED,          // DeepSpeed ZeRO
    CUSTOM
};

// Communication backends
enum class CommunicationBackend {
    NCCL,       // NVIDIA Collective Communications Library
    GLOO,       // Facebook's collective library
    MPI,        // Message Passing Interface
    CUSTOM
};

// Node role in distributed training
enum class NodeRole {
    MASTER,     // Master/coordinator node
    WORKER,     // Worker node
    PARAMETER_SERVER  // Parameter server (for PS strategy)
};

// Training configuration
struct DistributedConfig {
    DistributedStrategy strategy;
    CommunicationBackend backend;
    int world_size;             // Total number of nodes
    int rank;                   // Current node rank
    int local_rank;             // Local GPU rank
    std::string master_addr;    // Master node address
    int master_port;            // Master node port
    int num_workers;            // Number of data loading workers
    int gradient_accumulation_steps;
    bool use_mixed_precision;
    float learning_rate;
    int batch_size;
    
    DistributedConfig()
        : strategy(DistributedStrategy::DATA_PARALLEL)
        , backend(CommunicationBackend::NCCL)
        , world_size(1)
        , rank(0)
        , local_rank(0)
        , master_port(29500)
        , num_workers(4)
        , gradient_accumulation_steps(1)
        , use_mixed_precision(true)
        , learning_rate(0.0001f)
        , batch_size(32) {}
};

// Training statistics
struct TrainingStats {
    int epoch;
    int step;
    float loss;
    float learning_rate;
    float throughput_samples_per_sec;
    float gpu_utilization;
    size_t memory_used_mb;
    double time_per_step_ms;
    
    TrainingStats()
        : epoch(0)
        , step(0)
        , loss(0.0f)
        , learning_rate(0.0f)
        , throughput_samples_per_sec(0.0f)
        , gpu_utilization(0.0f)
        , memory_used_mb(0)
        , time_per_step_ms(0.0) {}
};

// Gradient synchronization
struct GradientSyncConfig {
    bool all_reduce;
    bool gradient_compression;
    float compression_ratio;
    bool overlap_communication;
    bool bucket_gradients;
    int bucket_size_mb;
    
    GradientSyncConfig()
        : all_reduce(true)
        , gradient_compression(false)
        , compression_ratio(0.5f)
        , overlap_communication(true)
        , bucket_gradients(true)
        , bucket_size_mb(25) {}
};

// Checkpoint configuration
struct CheckpointConfig {
    std::string checkpoint_dir;
    int save_every_n_steps;
    int save_every_n_epochs;
    int keep_last_n_checkpoints;
    bool save_optimizer_state;
    bool compress_checkpoints;
    
    CheckpointConfig()
        : checkpoint_dir("checkpoints")
        , save_every_n_steps(1000)
        , save_every_n_epochs(1)
        , keep_last_n_checkpoints(3)
        , save_optimizer_state(true)
        , compress_checkpoints(false) {}
};

// Forward declarations
class IDistributedBackend;
class DistributedTrainer;
class GradientSynchronizer;
class CheckpointManager;

/**
 * DistributedTrainer - Main distributed training coordinator
 */
class DistributedTrainer {
public:
    DistributedTrainer();
    ~DistributedTrainer();
    
    // Initialize distributed training
    bool initialize(const DistributedConfig& config);
    void shutdown();
    
    // Training loop
    bool trainEpoch(int epoch);
    bool trainStep();
    
    // Synchronization
    void barrier();
    void allReduce(std::vector<float>& data);
    void broadcast(std::vector<float>& data, int src_rank);
    
    // Gradient handling
    void synchronizeGradients();
    void scaleGradients(float factor);
    void zeroGradients();
    
    // Checkpointing
    bool saveCheckpoint(const std::string& path);
    bool loadCheckpoint(const std::string& path);
    
    // Statistics
    TrainingStats getStats() const;
    void resetStats();
    
    // Configuration
    void setLearningRate(float lr);
    float getLearningRate() const;
    
    // Status
    bool isInitialized() const { return initialized_; }
    bool isMaster() const { return config_.rank == 0; }
    int getRank() const { return config_.rank; }
    int getWorldSize() const { return config_.world_size; }
    
    // Callbacks
    using StepCallback = std::function<void(const TrainingStats&)>;
    using EpochCallback = std::function<void(int, const TrainingStats&)>;
    void setStepCallback(StepCallback callback);
    void setEpochCallback(EpochCallback callback);
    
private:
    DistributedConfig config_;
    GradientSyncConfig grad_sync_config_;
    CheckpointConfig checkpoint_config_;
    
    std::unique_ptr<IDistributedBackend> backend_;
    std::unique_ptr<GradientSynchronizer> grad_sync_;
    std::unique_ptr<CheckpointManager> checkpoint_mgr_;
    
    TrainingStats stats_;
    mutable std::mutex stats_mutex_;
    
    StepCallback step_callback_;
    EpochCallback epoch_callback_;
    
    bool initialized_;
    bool training_active_;
};

/**
 * IDistributedBackend - Communication backend interface
 */
class IDistributedBackend {
public:
    virtual ~IDistributedBackend() = default;
    
    // Initialize backend
    virtual bool initialize(const DistributedConfig& config) = 0;
    virtual void shutdown() = 0;
    
    // Collective operations
    virtual void allReduce(float* data, size_t count) = 0;
    virtual void allGather(const float* send_data, float* recv_data, size_t count) = 0;
    virtual void broadcast(float* data, size_t count, int src_rank) = 0;
    virtual void barrier() = 0;
    
    // Point-to-point
    virtual void send(const float* data, size_t count, int dst_rank) = 0;
    virtual void recv(float* data, size_t count, int src_rank) = 0;
    
    // Information
    virtual std::string getName() const = 0;
    virtual bool isAvailable() const = 0;
};

/**
 * NCCLBackend - NCCL implementation
 */
class NCCLBackend : public IDistributedBackend {
public:
    bool initialize(const DistributedConfig& config) override;
    void shutdown() override;
    void allReduce(float* data, size_t count) override;
    void allGather(const float* send_data, float* recv_data, size_t count) override;
    void broadcast(float* data, size_t count, int src_rank) override;
    void barrier() override;
    void send(const float* data, size_t count, int dst_rank) override;
    void recv(float* data, size_t count, int src_rank) override;
    std::string getName() const override { return "NCCL"; }
    bool isAvailable() const override;
    
private:
    void* comm_;  // ncclComm_t
    bool initialized_;
};

/**
 * GLOOBackend - GLOO implementation
 */
class GLOOBackend : public IDistributedBackend {
public:
    bool initialize(const DistributedConfig& config) override;
    void shutdown() override;
    void allReduce(float* data, size_t count) override;
    void allGather(const float* send_data, float* recv_data, size_t count) override;
    void broadcast(float* data, size_t count, int src_rank) override;
    void barrier() override;
    void send(const float* data, size_t count, int dst_rank) override;
    void recv(float* data, size_t count, int src_rank) override;
    std::string getName() const override { return "GLOO"; }
    bool isAvailable() const override;
    
private:
    void* context_;  // gloo::Context
    bool initialized_;
};

/**
 * GradientSynchronizer - Gradient synchronization coordinator
 */
class GradientSynchronizer {
public:
    GradientSynchronizer(IDistributedBackend* backend);
    
    void configure(const GradientSyncConfig& config);
    void synchronize(std::vector<float>& gradients);
    void compressGradients(std::vector<float>& gradients, float ratio);
    void decompressGradients(std::vector<float>& gradients);
    
private:
    IDistributedBackend* backend_;
    GradientSyncConfig config_;
};

/**
 * CheckpointManager - Distributed checkpoint management
 */
class CheckpointManager {
public:
    CheckpointManager();
    
    void configure(const CheckpointConfig& config);
    bool save(const std::string& tag, int rank);
    bool load(const std::string& tag, int rank);
    std::vector<std::string> listCheckpoints();
    bool deleteCheckpoint(const std::string& tag);
    
private:
    CheckpointConfig config_;
    std::vector<std::string> checkpoint_history_;
};

// Global distributed trainer accessor
DistributedTrainer* getDistributedTrainer();
void setDistributedTrainer(std::unique_ptr<DistributedTrainer> trainer);

// Utility functions
std::string strategyToString(DistributedStrategy strategy);
std::string backendToString(CommunicationBackend backend);
DistributedStrategy stringToStrategy(const std::string& str);
CommunicationBackend stringToBackend(const std::string& str);

} // namespace distributed
} // namespace rawrxd
