#include "rawrxd/distributed/TensorParallel.hpp"
#include <algorithm>
#include <numeric>

namespace rawrxd {
namespace distributed {

TensorParallel::TensorParallel() = default;

TensorParallel::~TensorParallel() {
    if (initialized_) {
        CleanupCommunication();
    }
}

bool TensorParallel::Initialize(const TensorParallelConfig& config) {
    config_ = config;
    
    if (config_.deviceIds.empty()) {
        // Auto-detect devices
        config_.deviceIds = DeviceManager::GetInstance().GetGPUDevices();
        if (config_.deviceIds.empty()) {
            config_.deviceIds.push_back(0); // Use CPU
        }
    }
    
    config_.worldSize = static_cast<int>(config_.deviceIds.size());
    if (config_.worldSize == 0) {
        config_.worldSize = 1;
        config_.deviceIds.push_back(0);
    }
    
    // Validate rank
    if (config_.rank >= config_.worldSize) {
        config_.rank = 0;
    }
    
    // Allocate communication buffers
    sendBuffers_.resize(config_.worldSize);
    recvBuffers_.resize(config_.worldSize);
    
    initialized_ = SetupCommunication();
    return initialized_;
}

bool TensorParallel::SetupCommunication() {
    // In a real implementation, this would set up NCCL or similar
    // For now, we just validate devices
    for (int deviceId : config_.deviceIds) {
        auto info = DeviceManager::GetInstance().GetDeviceInfo(deviceId);
        if (!info.isAvailable) {
            return false;
        }
    }
    return true;
}

void TensorParallel::CleanupCommunication() {
    // Cleanup NCCL communicators, etc.
    sendBuffers_.clear();
    recvBuffers_.clear();
}

std::vector<std::vector<float>> TensorParallel::SplitAttentionHeads(const std::vector<float>& weights) {
    std::vector<std::vector<float>> splits(config_.worldSize);
    
    if (config_.numAttentionHeads == 0 || config_.worldSize == 0) {
        splits[0] = weights;
        return splits;
    }
    
    int headsPerDevice = config_.numAttentionHeads / config_.worldSize;
    int remainder = config_.numAttentionHeads % config_.worldSize;
    
    size_t offset = 0;
    for (int i = 0; i < config_.worldSize; ++i) {
        int numHeads = headsPerDevice + (i < remainder ? 1 : 0);
        size_t splitSize = (weights.size() / config_.numAttentionHeads) * numHeads;
        
        if (offset + splitSize <= weights.size()) {
            splits[i].assign(weights.begin() + offset, weights.begin() + offset + splitSize);
        }
        offset += splitSize;
    }
    
    return splits;
}

std::vector<std::vector<float>> TensorParallel::SplitFFNColumn(const std::vector<float>& weights) {
    std::vector<std::vector<float>> splits(config_.worldSize);
    
    if (config_.worldSize == 0) {
        splits[0] = weights;
        return splits;
    }
    
    // Column parallel: split output dimension
    size_t splitSize = weights.size() / config_.worldSize;
    for (int i = 0; i < config_.worldSize; ++i) {
        size_t start = i * splitSize;
        size_t end = (i == config_.worldSize - 1) ? weights.size() : start + splitSize;
        splits[i].assign(weights.begin() + start, weights.begin() + end);
    }
    
    return splits;
}

std::vector<std::vector<float>> TensorParallel::SplitFFNRow(const std::vector<float>& weights) {
    std::vector<std::vector<float>> splits(config_.worldSize);
    
    if (config_.worldSize == 0) {
        splits[0] = weights;
        return splits;
    }
    
    // Row parallel: split input dimension
    // For simplicity, same as column split in this implementation
    size_t splitSize = weights.size() / config_.worldSize;
    for (int i = 0; i < config_.worldSize; ++i) {
        size_t start = i * splitSize;
        size_t end = (i == config_.worldSize - 1) ? weights.size() : start + splitSize;
        splits[i].assign(weights.begin() + start, weights.begin() + end);
    }
    
    return splits;
}

bool TensorParallel::AllReduce(std::vector<float>& data) {
    if (config_.worldSize <= 1) return true;
    
    // Simple CPU-based all-reduce (sum)
    // In production, use NCCL for GPU all-reduce
    
    std::vector<float> result(data.size(), 0.0f);
    
    // Gather from all ranks
    for (int rank = 0; rank < config_.worldSize; ++rank) {
        if (rank == config_.rank) {
            for (size_t i = 0; i < data.size(); ++i) {
                result[i] += data[i];
            }
        } else {
            // In real implementation, receive from other ranks
            // For now, just use local data
            for (size_t i = 0; i < data.size(); ++i) {
                result[i] += data[i]; // Should receive from rank
            }
        }
    }
    
    // Broadcast result
    data = result;
    return true;
}

bool TensorParallel::AllReduceAsync(std::vector<float>& data, std::function<void()> callback) {
    // Execute synchronously for now
    bool result = AllReduce(data);
    if (callback) {
        callback();
    }
    return result;
}

bool TensorParallel::AllGather(const std::vector<float>& localData, std::vector<float>& globalData) {
    if (config_.worldSize <= 1) {
        globalData = localData;
        return true;
    }
    
    globalData.resize(localData.size() * config_.worldSize);
    
    // Copy local data to appropriate position
    size_t offset = config_.rank * localData.size();
    std::copy(localData.begin(), localData.end(), globalData.begin() + offset);
    
    // In real implementation, gather from all other ranks
    // For now, just copy local data to all positions
    for (int rank = 0; rank < config_.worldSize; ++rank) {
        if (rank != config_.rank) {
            size_t destOffset = rank * localData.size();
            std::copy(localData.begin(), localData.end(), globalData.begin() + destOffset);
        }
    }
    
    return true;
}

bool TensorParallel::Broadcast(std::vector<float>& data, int rootRank) {
    if (config_.worldSize <= 1) return true;
    
    // In real implementation, root sends to all others
    // For now, data is already on all ranks
    return true;
}

bool TensorParallel::ReduceScatter(const std::vector<float>& sendData, std::vector<float>& recvData) {
    if (config_.worldSize <= 1) {
        recvData = sendData;
        return true;
    }
    
    // Reduce then scatter
    std::vector<float> reduced(sendData.size());
    for (size_t i = 0; i < sendData.size(); ++i) {
        reduced[i] = sendData[i]; // Should sum from all ranks
    }
    
    // Scatter to ranks
    size_t chunkSize = reduced.size() / config_.worldSize;
    size_t start = config_.rank * chunkSize;
    size_t end = (config_.rank == config_.worldSize - 1) ? reduced.size() : start + chunkSize;
    
    recvData.assign(reduced.begin() + start, reduced.begin() + end);
    return true;
}

void TensorParallel::Barrier() {
    // Synchronize all devices
    for (int deviceId : config_.deviceIds) {
        DeviceManager::GetInstance().SynchronizeDevice(deviceId);
    }
}

bool TensorParallel::DistributedMatMul(const std::vector<float>& A, const std::vector<float>& B,
                                        std::vector<float>& C, int M, int N, int K) {
    if (config_.worldSize <= 1) {
        // Single device - do full multiplication
        C.resize(M * N);
        for (int i = 0; i < M; ++i) {
            for (int j = 0; j < N; ++j) {
                float sum = 0.0f;
                for (int k = 0; k < K; ++k) {
                    sum += A[i * K + k] * B[k * N + j];
                }
                C[i * N + j] = sum;
            }
        }
        return true;
    }
    
    // Split M dimension across devices
    int mPerDevice = M / config_.worldSize;
    int mStart = config_.rank * mPerDevice;
    int mEnd = (config_.rank == config_.worldSize - 1) ? M : mStart + mPerDevice;
    int localM = mEnd - mStart;
    
    // Local computation
    std::vector<float> localC(localM * N);
    for (int i = 0; i < localM; ++i) {
        for (int j = 0; j < N; ++j) {
            float sum = 0.0f;
            for (int k = 0; k < K; ++k) {
                sum += A[(mStart + i) * K + k] * B[k * N + j];
            }
            localC[i * N + j] = sum;
        }
    }
    
    // Gather results
    C.resize(M * N);
    std::copy(localC.begin(), localC.end(), C.begin() + mStart * N);
    
    // In real implementation, all-gather from all ranks
    return true;
}

bool TensorParallel::ParallelAttention(const std::vector<float>& query, const std::vector<float>& key,
                                        const std::vector<float>& value, std::vector<float>& output,
                                        int batchSize, int seqLen, int numHeads, int headDim) {
    // Split heads across devices
    int headsPerDevice = numHeads / config_.worldSize;
    int remainder = numHeads % config_.worldSize;
    
    int localHeads = headsPerDevice + (config_.rank < remainder ? 1 : 0);
    int headStart = config_.rank * headsPerDevice + std::min(config_.rank, remainder);
    
    // Compute attention for local heads
    std::vector<float> localOutput(batchSize * seqLen * localHeads * headDim);
    
    for (int b = 0; b < batchSize; ++b) {
        for (int h = 0; h < localHeads; ++h) {
            int globalHead = headStart + h;
            for (int s = 0; s < seqLen; ++s) {
                // Compute attention scores
                std::vector<float> scores(seqLen);
                float maxScore = -std::numeric_limits<float>::infinity();
                
                for (int t = 0; t < seqLen; ++t) {
                    float dot = 0.0f;
                    for (int d = 0; d < headDim; ++d) {
                        int qIdx = ((b * numHeads + globalHead) * seqLen + s) * headDim + d;
                        int kIdx = ((b * numHeads + globalHead) * seqLen + t) * headDim + d;
                        dot += query[qIdx] * key[kIdx];
                    }
                    scores[t] = dot / std::sqrt(static_cast<float>(headDim));
                    maxScore = std::max(maxScore, scores[t]);
                }
                
                // Softmax
                float sumExp = 0.0f;
                for (int t = 0; t < seqLen; ++t) {
                    scores[t] = std::exp(scores[t] - maxScore);
                    sumExp += scores[t];
                }
                for (int t = 0; t < seqLen; ++t) {
                    scores[t] /= sumExp;
                }
                
                // Weighted sum of values
                for (int d = 0; d < headDim; ++d) {
                    float sum = 0.0f;
                    for (int t = 0; t < seqLen; ++t) {
                        int vIdx = ((b * numHeads + globalHead) * seqLen + t) * headDim + d;
                        sum += scores[t] * value[vIdx];
                    }
                    int outIdx = ((b * localHeads + h) * seqLen + s) * headDim + d;
                    localOutput[outIdx] = sum;
                }
            }
        }
    }
    
    // Gather outputs from all devices
    output.resize(batchSize * seqLen * numHeads * headDim);
    
    // Copy local output to global output
    for (int b = 0; b < batchSize; ++b) {
        for (int h = 0; h < localHeads; ++h) {
            int globalHead = headStart + h;
            for (int s = 0; s < seqLen; ++s) {
                for (int d = 0; d < headDim; ++d) {
                    int localIdx = ((b * localHeads + h) * seqLen + s) * headDim + d;
                    int globalIdx = ((b * numHeads + globalHead) * seqLen + s) * headDim + d;
                    output[globalIdx] = localOutput[localIdx];
                }
            }
        }
    }
    
    // In real implementation, all-gather from all ranks
    return true;
}

// ParallelismPlanner implementation
ParallelStrategyConfig ParallelismPlanner::RecommendStrategy(
    const std::vector<DeviceInfo>& devices,
    size_t modelSizeBytes,
    int numLayers,
    int hiddenSize,
    int numAttentionHeads,
    int batchSize) {
    
    ParallelStrategyConfig config;
    
    // Filter to available GPU devices
    std::vector<DeviceInfo> gpus;
    for (const auto& device : devices) {
        if (device.type == DeviceType::CUDA_GPU || 
            device.type == DeviceType::ROCM_GPU) {
            gpus.push_back(device);
        }
    }
    
    int numDevices = static_cast<int>(gpus.size());
    if (numDevices == 0) {
        config.strategy = ParallelStrategy::NONE;
        return config;
    }
    
    // Check if model fits on single device
    if (CanFitOnSingleDevice(gpus[0], modelSizeBytes)) {
        // Single device is sufficient
        config.strategy = ParallelStrategy::NONE;
        config.tensorParallelDevices.push_back(gpus[0].deviceId);
        return config;
    }
    
    // Calculate optimal parallelism
    int optimalTP = OptimalTensorParallelSize(gpus, modelSizeBytes);
    int optimalPP = OptimalPipelineParallelSize(numLayers, numDevices / optimalTP);
    
    if (optimalTP > 1 && optimalPP == 1) {
        // Pure tensor parallelism
        config.strategy = ParallelStrategy::TENSOR_PARALLEL;
        config.tensorParallelSize = optimalTP;
        for (int i = 0; i < optimalTP && i < numDevices; ++i) {
            config.tensorParallelDevices.push_back(gpus[i].deviceId);
        }
    } else if (optimalPP > 1) {
        // Pipeline parallelism
        config.strategy = ParallelStrategy::PIPELINE_PARALLEL;
        config.pipelineParallelSize = optimalPP;
        
        int devicesPerStage = numDevices / optimalPP;
        for (int stage = 0; stage < optimalPP; ++stage) {
            std::vector<int> stageDevices;
            for (int i = 0; i < devicesPerStage; ++i) {
                int idx = stage * devicesPerStage + i;
                if (idx < numDevices) {
                    stageDevices.push_back(gpus[idx].deviceId);
                }
            }
            config.pipelineStageDevices.push_back(stageDevices);
        }
    }
    
    return config;
}

std::vector<size_t> ParallelismPlanner::CalculateMemoryPerDevice(
    const ParallelStrategyConfig& config,
    size_t modelSizeBytes,
    int batchSize,
    int seqLength) {
    
    std::vector<size_t> memoryPerDevice;
    
    switch (config.strategy) {
        case ParallelStrategy::NONE:
            memoryPerDevice.push_back(modelSizeBytes);
            break;
            
        case ParallelStrategy::TENSOR_PARALLEL:
            memoryPerDevice.resize(config.tensorParallelSize, 
                                   modelSizeBytes / config.tensorParallelSize);
            break;
            
        case ParallelStrategy::PIPELINE_PARALLEL:
            memoryPerDevice.resize(config.pipelineParallelSize,
                                   modelSizeBytes / config.pipelineParallelSize);
            break;
            
        case ParallelStrategy::HYBRID:
            // Complex calculation for hybrid
            int totalDevices = config.tensorParallelSize * config.pipelineParallelSize;
            memoryPerDevice.resize(totalDevices, 
                                   modelSizeBytes / totalDevices);
            break;
    }
    
    return memoryPerDevice;
}

double ParallelismPlanner::EstimateThroughput(
    const ParallelStrategyConfig& config,
    const std::vector<DeviceInfo>& devices) {
    
    // Simplified throughput estimation
    double baseThroughput = 100.0; // tokens/sec per device
    
    switch (config.strategy) {
        case ParallelStrategy::NONE:
            return baseThroughput;
            
        case ParallelStrategy::TENSOR_PARALLEL:
            // Tensor parallel has communication overhead
            return baseThroughput * config.tensorParallelSize * 0.85;
            
        case ParallelStrategy::PIPELINE_PARALLEL:
            // Pipeline has bubble overhead
            return baseThroughput * config.pipelineParallelSize * 0.75;
            
        case ParallelStrategy::HYBRID:
            int totalDevices = config.tensorParallelSize * config.pipelineParallelSize;
            return baseThroughput * totalDevices * 0.65;
    }
    
    return baseThroughput;
}

bool ParallelismPlanner::CanFitOnSingleDevice(const DeviceInfo& device, size_t modelSizeBytes) {
    // Leave 20% headroom for activations and overhead
    return modelSizeBytes < device.freeMemoryBytes * 0.8;
}

int ParallelismPlanner::OptimalTensorParallelSize(const std::vector<DeviceInfo>& devices, 
                                                   size_t modelSizeBytes) {
    int numDevices = static_cast<int>(devices.size());
    if (numDevices == 0) return 1;
    
    // Find minimum devices needed to fit model
    for (int tp = 1; tp <= numDevices; ++tp) {
        size_t perDevice = modelSizeBytes / tp;
        // Check if all tp devices have enough memory
        bool fits = true;
        for (int i = 0; i < tp; ++i) {
            if (perDevice >= devices[i].freeMemoryBytes * 0.8) {
                fits = false;
                break;
            }
        }
        if (fits) return tp;
    }
    
    return numDevices;
}

int ParallelismPlanner::OptimalPipelineParallelSize(int numLayers, int numDevices) {
    if (numDevices <= 1) return 1;
    
    // Aim for at least 2 layers per stage
    int maxPP = numLayers / 2;
    return std::min(numDevices, maxPP);
}

} // namespace distributed
} // namespace rawrxd
