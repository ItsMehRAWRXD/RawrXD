#pragma once

#include <vector>
#include <memory>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>
#include "rawrxd/distributed/DeviceManager.hpp"

namespace rawrxd {
namespace distributed {

// Pipeline stage configuration
struct PipelineStageConfig {
    int stageId = 0;
    int numStages = 1;
    std::vector<int> deviceIds;
    int startLayer = 0;
    int endLayer = 0;
    bool useTensorParallel = false;
    TensorParallelConfig tpConfig;
};

// Micro-batch for pipeline parallelism
struct MicroBatch {
    int batchId = 0;
    std::vector<float> activations;
    std::vector<int> tokenIds;
    int seqLength = 0;
    int numTokens = 0;
    bool isFirstStage = false;
    bool isLastStage = false;
    std::chrono::high_resolution_clock::time_point startTime;
};

// Pipeline stage execution
class PipelineStage {
public:
    PipelineStage();
    ~PipelineStage();

    // Initialize stage
    bool Initialize(const PipelineStageConfig& config);
    
    // Execute forward pass for this stage
    bool Forward(const MicroBatch& input, MicroBatch& output);
    
    // Execute backward pass (for training)
    bool Backward(const MicroBatch& gradOutput, MicroBatch& gradInput);
    
    // Get stage info
    int GetStageId() const { return config_.stageId; }
    int GetNumLayers() const { return config_.endLayer - config_.startLayer; }
    
    // Load model layers for this stage
    bool LoadLayers(const std::string& modelPath);
    
    // Unload layers
    void UnloadLayers();
    
    // Check if loaded
    bool IsLoaded() const;

private:
    PipelineStageConfig config_;
    bool initialized_ = false;
    bool layersLoaded_ = false;
    
    // Model layers for this stage
    // std::vector<std::unique_ptr<TransformerLayer>> layers_;
    
    // Device management
    std::unique_ptr<DeviceGuard> deviceGuard_;
    
    // Forward implementation
    bool ExecuteForward(const std::vector<float>& input, std::vector<float>& output);
};

// Pipeline parallelism scheduler
enum class PipelineSchedule {
    FILL_DRAIN,      // Simple fill then drain
    GPIPE,          // GPipe with bubble
    PIPE_DREAM,     // PipeDream with backward
    INTERLEAVED     // Interleaved 1F1B
};

// Pipeline parallel execution engine
class PipelineParallel {
public:
    PipelineParallel();
    ~PipelineParallel();

    // Initialize pipeline parallelism
    bool Initialize(const std::vector<PipelineStageConfig>& stageConfigs,
                    PipelineSchedule schedule = PipelineSchedule::GPIPE);
    
    // Execute inference with pipeline parallelism
    std::vector<float> Forward(const std::vector<float>& input);
    
    // Execute with micro-batching
    std::vector<std::vector<float>> ForwardMicroBatches(
        const std::vector<std::vector<float>>& microBatches);
    
    // Get pipeline stats
    struct Stats {
        int numStages = 0;
        int numMicroBatches = 0;
        double throughputSamplesPerSec = 0.0;
        double avgLatencyMs = 0.0;
        double bubbleOverheadPercent = 0.0;
        std::vector<double> stageLatencyMs;
    };
    Stats GetStats() const;
    
    // Warmup pipeline
    void Warmup(int numWarmupBatches);
    
    // Shutdown
    void Shutdown();

private:
    std::vector<std::unique_ptr<PipelineStage>> stages_;
    PipelineSchedule schedule_;
    bool initialized_ = false;
    bool running_ = false;
    
    // Communication queues between stages
    std::vector<std::queue<MicroBatch>> stageQueues_;
    std::vector<std::mutex> queueMutexes_;
    std::vector<std::condition_variable> queueCVs_;
    
    // Worker threads
    std::vector<std::thread> stageThreads_;
    
    // Statistics
    mutable std::mutex statsMutex_;
    Stats stats_;
    std::vector<std::chrono::high_resolution_clock::duration> stageLatencies_;
    
    // Execution
    void StageWorker(int stageId);
    bool SendToNextStage(int currentStage, const MicroBatch& batch);
    bool ReceiveFromPreviousStage(int currentStage, MicroBatch& batch);
    
    // Schedule implementations
    std::vector<float> ExecuteFillDrain(const std::vector<float>& input);
    std::vector<float> ExecuteGPipe(const std::vector<float>& input);
    std::vector<std::vector<float>> ExecuteInterleaved1F1B(
        const std::vector<std::vector<float>>& microBatches);
};

// Pipeline batching configuration
struct PipelineBatchConfig {
    int microBatchSize = 1;
    int numMicroBatches = 4;
    PipelineSchedule schedule = PipelineSchedule::GPIPE;
    bool overlapCommunication = true;
    bool enableActivationCheckpointing = false;
};

// High-level pipeline inference engine
class PipelineInferenceEngine {
public:
    PipelineInferenceEngine();
    ~PipelineInferenceEngine();

    // Initialize with model and devices
    bool Initialize(const std::string& modelPath,
                    const std::vector<int>& deviceIds,
                    const PipelineBatchConfig& config);
    
    // Generate with pipeline parallelism
    std::string Generate(const std::string& prompt, int maxNewTokens);
    
    // Batch generate
    std::vector<std::string> GenerateBatch(const std::vector<std::string>& prompts,
                                             int maxNewTokens);
    
    // Get performance stats
    PipelineParallel::Stats GetStats() const;
    
    // Shutdown
    void Shutdown();

private:
    std::unique_ptr<PipelineParallel> pipeline_;
    PipelineBatchConfig config_;
    bool initialized_ = false;
    
    // Tokenization (placeholder)
    std::vector<int> Tokenize(const std::string& text);
    std::string Detokenize(const std::vector<int>& tokens);
    
    // Embedding lookup
    std::vector<float> EmbeddingsLookup(const std::vector<int>& tokenIds);
};

} // namespace distributed
} // namespace rawrxd
