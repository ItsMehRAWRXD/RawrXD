#pragma once

#include <vector>
#include <memory>
#include <thread>
#include <future>
#include <functional>
#include "rawrxd/distributed/DeviceManager.hpp"

namespace rawrxd {
namespace distributed {

// Tensor parallel configuration
struct TensorParallelConfig {
    int worldSize = 1;           // Total number of devices
    int rank = 0;                // Current device rank
    std::vector<int> deviceIds;  // Device IDs to use
    int numAttentionHeads = 0;   // For head parallelism
    int numFFNSplits = 1;        // For FFN column/row parallelism
    bool useNCCL = true;         // Use NCCL for communication
    bool asyncCommunication = true;
};

// Distributed tensor operations
class TensorParallel {
public:
    TensorParallel();
    ~TensorParallel();

    // Initialize tensor parallelism
    bool Initialize(const TensorParallelConfig& config);
    
    // Check if initialized
    bool IsInitialized() const { return initialized_; }
    
    // Get configuration
    const TensorParallelConfig& GetConfig() const { return config_; }
    
    // Get world size and rank
    int GetWorldSize() const { return config_.worldSize; }
    int GetRank() const { return config_.rank; }
    
    // Split operations (for model loading)
    std::vector<std::vector<float>> SplitAttentionHeads(const std::vector<float>& weights);
    std::vector<std::vector<float>> SplitFFNColumn(const std::vector<float>& weights);
    std::vector<std::vector<float>> SplitFFNRow(const std::vector<float>& weights);
    
    // All-reduce (for gradient synchronization)
    bool AllReduce(std::vector<float>& data);
    bool AllReduceAsync(std::vector<float>& data, std::function<void()> callback);
    
    // All-gather (for collecting outputs)
    bool AllGather(const std::vector<float>& localData, std::vector<float>& globalData);
    
    // Broadcast (for sharing parameters)
    bool Broadcast(std::vector<float>& data, int rootRank = 0);
    
    // Reduce-scatter (for distributed computation)
    bool ReduceScatter(const std::vector<float>& sendData, std::vector<float>& recvData);
    
    // Barrier synchronization
    void Barrier();
    
    // Distributed matrix multiplication
    bool DistributedMatMul(const std::vector<float>& A, const std::vector<float>& B,
                           std::vector<float>& C, int M, int N, int K);
    
    // Parallel attention computation
    bool ParallelAttention(const std::vector<float>& query, const std::vector<float>& key,
                           const std::vector<float>& value, std::vector<float>& output,
                           int batchSize, int seqLen, int numHeads, int headDim);

private:
    TensorParallelConfig config_;
    bool initialized_ = false;
    
    // Communication buffers
    std::vector<std::vector<float>> sendBuffers_;
    std::vector<std::vector<float>> recvBuffers_;
    
    // Thread pool for async operations
    std::vector<std::thread> workerThreads_;
    
    // Synchronization
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<int> completedCount_{0};
    
    // Internal communication
    bool SetupCommunication();
    void CleanupCommunication();
    bool SynchronizeDevices();
};

// Model parallelism strategy
enum class ParallelStrategy {
    NONE,           // No parallelism
    TENSOR_PARALLEL, // Split layers across devices
    PIPELINE_PARALLEL, // Pipeline stages
    HYBRID          // Combination of both
};

// Parallel strategy configuration
struct ParallelStrategyConfig {
    ParallelStrategy strategy = ParallelStrategy::NONE;
    int tensorParallelSize = 1;
    int pipelineParallelSize = 1;
    std::vector<int> tensorParallelDevices;
    std::vector<std::vector<int>> pipelineStageDevices;
};

// Automatic parallelism planner
class ParallelismPlanner {
public:
    // Analyze model and recommend parallelism strategy
    static ParallelStrategyConfig RecommendStrategy(
        const std::vector<DeviceInfo>& devices,
        size_t modelSizeBytes,
        int numLayers,
        int hiddenSize,
        int numAttentionHeads,
        int batchSize = 1);
    
    // Calculate memory requirements per device
    static std::vector<size_t> CalculateMemoryPerDevice(
        const ParallelStrategyConfig& config,
        size_t modelSizeBytes,
        int batchSize,
        int seqLength);
    
    // Estimate throughput
    static double EstimateThroughput(
        const ParallelStrategyConfig& config,
        const std::vector<DeviceInfo>& devices);

private:
    static bool CanFitOnSingleDevice(const DeviceInfo& device, size_t modelSizeBytes);
    static int OptimalTensorParallelSize(const std::vector<DeviceInfo>& devices, size_t modelSizeBytes);
    static int OptimalPipelineParallelSize(int numLayers, int numDevices);
};

} // namespace distributed
} // namespace rawrxd
