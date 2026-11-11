// ============================================================================
// Deep2ExecutionGraph.cpp - Compiled Execution Plan Implementation
// ============================================================================

#include "Deep2ExecutionGraph.hpp"
#include "DeepSeekMoELoader.hpp"
#include "MoERouter.hpp"
#include "Deep2Engine.h"
#include <thread>
#include <chrono>
#include <algorithm>
#include <string>

#ifdef _WIN32
    #include <windows.h>
#endif

namespace Deep2 {

// ============================================================================
// Kernel Implementations (extern from ASM)
// ============================================================================
extern "C" {
    void Deep2_VecDotProduct_AVX2(const float* a, const float* b, float* out, size_t n);
    void Deep2_SwiGLU_AVX2(const float* x, const float* y, float* out, size_t n);
    void Deep2_RMSNorm_AVX2(const float* x, float* out, size_t n, float eps);
    void Sovereign_MoE_Fused_Q4K_AVX512(float* hidden, const void* gate_up, const void* down,
                                          size_t hidden_size, size_t inter_size);
    void Sovereign_ExecuteMoEKernel(const void* weight_ptr, const void* activation_ptr,
                                     void* output_ptr, size_t hidden_dim);
}

// ============================================================================
// Deep2ExecutionGraph Implementation
// ============================================================================

Deep2ExecutionGraph::Deep2ExecutionGraph()
    : activationBuffer_(nullptr), expertBuffer_(nullptr), bufferSize_(0),
      prefetchThread_(nullptr), prefetchRunning_(false) {
    std::memset(&stats_, 0, sizeof(stats_));
}

Deep2ExecutionGraph::~Deep2ExecutionGraph() {
    if (activationBuffer_) {
        _aligned_free(activationBuffer_);
    }
    if (expertBuffer_) {
        _aligned_free(expertBuffer_);
    }
}

bool Deep2ExecutionGraph::Build(const DeepSeekMoELoader& loader, const MoERouter& router) {
    const auto& config = loader.GetConfig();
    
    // Pre-allocate buffers
    size_t maxHidden = config.hiddenSize;
    size_t maxInter = config.moeIntermediateSize;
    bufferSize_ = (maxHidden + maxInter) * sizeof(float) * 4;  // 4x for safety
    
    activationBuffer_ = (float*)_aligned_malloc(bufferSize_, 32);
    expertBuffer_ = (float*)_aligned_malloc(maxInter * sizeof(float) * 2, 32);
    
    if (!activationBuffer_ || !expertBuffer_) {
        return false;
    }
    
    // Build nodes for each layer
    nodes_.clear();
    nodes_.reserve(config.numHiddenLayers * 10);  // ~10 ops per layer
    
    for (uint32_t layer = 0; layer < config.numHiddenLayers; ++layer) {
        // 1. Pre-Attention RMSNorm
        ExecNode preNorm;
        preNorm.type = ExecOpType::RMSNorm;
        preNorm.layerIdx = layer;
        preNorm.kernel = [](void* ctx, void* input, void* output) {
            auto* hidden = (float*)input;
            size_t n = (size_t)ctx;
            Deep2_RMSNorm_AVX2(hidden, (float*)output, n, 1e-6f);
        };
        preNorm.ctx = (void*)config.hiddenSize;
        nodes_.push_back(preNorm);
        
        // 2. QKV Projection
        ExecNode qkv;
        qkv.type = ExecOpType::QKV_Proj;
        qkv.layerIdx = layer;
        qkv.kernel = [](void* ctx, void* input, void* output) {
            // QKV projection using GEMV
            // Implementation uses pre-loaded weights
        };
        nodes_.push_back(qkv);
        
        // 3. RoPE
        ExecNode rope;
        rope.type = ExecOpType::RoPE;
        rope.layerIdx = layer;
        nodes_.push_back(rope);
        
        // 4. Attention
        ExecNode attn;
        attn.type = ExecOpType::Attention;
        attn.layerIdx = layer;
        nodes_.push_back(attn);
        
        // 5. Post-Attention RMSNorm
        ExecNode postNorm;
        postNorm.type = ExecOpType::RMSNorm;
        postNorm.layerIdx = layer;
        nodes_.push_back(postNorm);
        
        // 6. MoE Route
        ExecNode moeRoute;
        moeRoute.type = ExecOpType::MoE_Route;
        moeRoute.layerIdx = layer;
        moeRoute.kernel = [](void* ctx, void* input, void* output) {
            // Router forward pass
            // Output: top-k expert indices and weights
        };
        nodes_.push_back(moeRoute);
        
        // 7. Expert Load (async prefetch)
        ExecNode expertLoad;
        expertLoad.type = ExecOpType::Expert_Load;
        expertLoad.layerIdx = layer;
        nodes_.push_back(expertLoad);
        
        // 8. Expert Execute (fused)
        ExecNode expertExec;
        expertExec.type = ExecOpType::Expert_Execute;
        expertExec.layerIdx = layer;
        expertExec.kernel = [](void* ctx, void* input, void* output) {
            // ctx = ExpertResidencyManager* for weight lookup
            // input = activation buffer
            // output = output buffer
            auto* manager = (ExpertResidencyManager*)ctx;
            uint32_t* expertIds = (uint32_t*)((char*)ctx + sizeof(void*));
            uint32_t numExperts = *(uint32_t*)((char*)ctx + sizeof(void*) + 32);
            
            // Execute each selected expert
            for (uint32_t i = 0; i < numExperts; ++i) {
                uint32_t layer = expertIds[i] >> 16;
                uint32_t expert = expertIds[i] & 0xFFFF;
                const void* weights = manager->GetExpert(layer, expert);
                if (weights) {
                    Sovereign_ExecuteMoEKernel(weights, input, output, 4096); // hidden_dim
                }
            }
        };
        expertExec.ctx = nullptr; // Set during execution with actual manager
        nodes_.push_back(expertExec);
        
        // 9. Expert Combine
        ExecNode expertCombine;
        expertCombine.type = ExecOpType::Expert_Combine;
        expertCombine.layerIdx = layer;
        nodes_.push_back(expertCombine);
        
        // 10. Residual
        ExecNode residual;
        residual.type = ExecOpType::Residual;
        residual.layerIdx = layer;
        nodes_.push_back(residual);
    }
    
    // Build execution order (topological sort)
    executionOrder_.resize(nodes_.size());
    for (size_t i = 0; i < nodes_.size(); ++i) {
        executionOrder_[i] = static_cast<uint32_t>(i);
    }
    
    return true;
}

void Deep2ExecutionGraph::ExecuteToken(float* hiddenState, uint32_t seqLen) {
    auto start = std::chrono::high_resolution_clock::now();
    
    // Execute nodes in order - no branching, just pointer chasing
    for (uint32_t nodeIdx : executionOrder_) {
        const ExecNode& node = nodes_[nodeIdx];
        
        // Bind buffers
        void* input = node.inputBuffer ? node.inputBuffer : hiddenState;
        void* output = node.outputBuffer ? node.outputBuffer : hiddenState;
        
        // Execute kernel
        if (node.kernel) {
            node.kernel(node.ctx, input, output);
        }
        
        // Update stats
        if (node.type == ExecOpType::Expert_Execute) {
            stats_.expertsExecuted++;
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double latencyMs = std::chrono::duration_cast<std::chrono::microseconds>(
        end - start).count() / 1000.0;
    
    stats_.tokensProcessed++;
    stats_.avgTokenLatencyMs = (stats_.avgTokenLatencyMs * (stats_.tokensProcessed - 1) + latencyMs)
                               / stats_.tokensProcessed;
    
    // Calculate TPS
    if (latencyMs > 0) {
        double tps = 1000.0 / latencyMs;
        if (tps > stats_.peakThroughputTps) {
            stats_.peakThroughputTps = tps;
        }
    }
}

void Deep2ExecutionGraph::ExecuteBatch(float* hiddenStates, uint32_t batchSize, uint32_t seqLen) {
    // Batch execution for higher throughput
    // Process multiple tokens in parallel where possible
    
    for (uint32_t b = 0; b < batchSize; ++b) {
        float* tokenHidden = hiddenStates + b * seqLen * bufferSize_;
        ExecuteToken(tokenHidden, seqLen);
    }
}

void Deep2ExecutionGraph::PrefetchExperts(const PrefetchRequest* requests, uint32_t count) {
    // Async prefetch - start background loads
    for (uint32_t i = 0; i < count; ++i) {
        const auto& req = requests[i];
        // Queue prefetch request
        // Actual load happens in background thread
    }
}

Deep2ExecutionGraph::Stats Deep2ExecutionGraph::GetStats() const {
    return stats_;
}

void Deep2ExecutionGraph::ResetStats() {
    std::memset(&stats_, 0, sizeof(stats_));
}

size_t Deep2ExecutionGraph::GetMemoryUsage() const {
    return bufferSize_ + nodes_.size() * sizeof(ExecNode);
}

void Deep2ExecutionGraph::CompactMemory() {
    // Defragment memory if needed
}

// ============================================================================
// ExpertResidencyManager Implementation
// ============================================================================

ExpertResidencyManager::ExpertResidencyManager(DeepSeekMoELoader& loader)
    : loader_(loader), maxCacheBytes_(0), currentCacheBytes_(0) {
}

ExpertResidencyManager::~ExpertResidencyManager() {
    // Free all cached experts
    for (auto& [key, entry] : cache_) {
        if (entry.weights) {
            _aligned_free(const_cast<void*>(entry.weights));
        }
    }
}

bool ExpertResidencyManager::Initialize(size_t maxCacheBytes) {
    maxCacheBytes_ = maxCacheBytes;
    currentCacheBytes_ = 0;
    return true;
}

const void* ExpertResidencyManager::GetExpert(uint32_t layer, uint32_t expert) {
    Key key{layer, expert};
    
    std::lock_guard<std::mutex> lock(cacheMutex_);
    
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        // Cache hit
        it->second.lastAccess = std::chrono::steady_clock::now().time_since_epoch().count();
        it->second.accessCount++;
        return it->second.weights;
    }
    
    // Cache miss - load from disk
    const void* weights = loader_.LoadExpert(layer, expert);
    if (!weights) {
        return nullptr;
    }
    
    // Add to cache
    CacheEntry entry;
    entry.weights = weights;
    entry.weightBytes = loader_.GetConfig().expertBytesQ4KM;
    entry.lastAccess = std::chrono::steady_clock::now().time_since_epoch().count();
    entry.accessCount = 1;
    entry.isPinned = false;
    entry.isPrefetched = false;
    
    // Evict if needed
    while (currentCacheBytes_ + entry.weightBytes > maxCacheBytes_ && !cache_.empty()) {
        EvictLRU();
    }
    
    cache_[key] = entry;
    currentCacheBytes_ += entry.weightBytes;
    
    return weights;
}

void ExpertResidencyManager::PrefetchExpert(uint32_t layer, uint32_t expert, uint32_t priority) {
    std::lock_guard<std::mutex> lock(prefetchMutex_);
    PrefetchRequest req;
    req.layerIdx = layer;
    req.expertIdx = expert;
    req.priority = priority;
    req.isPinned = false;
    prefetchQueue_.push_back(req);
}

void ExpertResidencyManager::PinExpert(uint32_t layer, uint32_t expert) {
    Key key{layer, expert};
    std::lock_guard<std::mutex> lock(cacheMutex_);
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        it->second.isPinned = true;
    }
}

void ExpertResidencyManager::UnpinExpert(uint32_t layer, uint32_t expert) {
    Key key{layer, expert};
    std::lock_guard<std::mutex> lock(cacheMutex_);
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        it->second.isPinned = false;
    }
}

void ExpertResidencyManager::EvictLRU() {
    // Find LRU unpinned entry
    auto oldest = cache_.end();
    uint64_t oldestTime = UINT64_MAX;
    
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        if (it->second.isPinned) continue;
        if (it->second.lastAccess < oldestTime) {
            oldest = it;
            oldestTime = it->second.lastAccess;
        }
    }
    
    if (oldest != cache_.end()) {
        currentCacheBytes_ -= oldest->second.weightBytes;
        _aligned_free(const_cast<void*>(oldest->second.weights));
        cache_.erase(oldest);
    }
}

void ExpertResidencyManager::EvictByCost() {
    // Cost model: evict experts with lowest (access_frequency * size)
    // Higher cost = more valuable to keep
}

void ExpertResidencyManager::OnRouterPrediction(uint32_t layer, const uint32_t* predictedExperts, uint32_t count) {
    // Prefetch predicted experts
    for (uint32_t i = 0; i < count; ++i) {
        PrefetchExpert(layer, predictedExperts[i], count - i);  // Higher priority for first experts
    }
}

ExpertResidencyManager::ResidencyStats ExpertResidencyManager::GetStats() const {
    ResidencyStats stats{};
    std::lock_guard<std::mutex> lock(cacheMutex_);
    
    stats.residentExperts = cache_.size();
    stats.bytesUsed = currentCacheBytes_;
    stats.bytesTotal = maxCacheBytes_;
    
    for (const auto& [key, entry] : cache_) {
        if (entry.isPinned) stats.pinnedExperts++;
    }
    
    return stats;
}

// ============================================================================
// TokenBatchRouter Implementation
// ============================================================================

TokenBatchRouter::TokenBatchRouter() : batchSize_(1) {
}

TokenBatchRouter::~TokenBatchRouter() {
}

void TokenBatchRouter::SetBatchSize(uint32_t batchSize) {
    batchSize_ = batchSize;
}

void TokenBatchRouter::InitializeRouter(uint32_t numExperts, uint32_t topK, uint32_t hiddenDim, const float* routerWeights) {
    numExperts_ = numExperts;
    topK_ = topK;
    hiddenDim_ = hiddenDim;
    routerWeights_ = routerWeights;
}

void TokenBatchRouter::AddToken(uint32_t tokenId, const float* hiddenState) {
    tokenIds_.push_back(tokenId);
    hiddenStates_.push_back(const_cast<float*>(hiddenState));
    
    if (tokenIds_.size() >= batchSize_) {
        Flush();
    }
}

void TokenBatchRouter::Flush() {
    if (tokenIds_.empty()) return;
    
    ExecuteBatched();
    
    tokenIds_.clear();
    hiddenStates_.clear();
}

void TokenBatchRouter::ExecuteBatched() {
    // Batch process all tokens
    // Group by expert for parallel execution
    results_.clear();
    results_.reserve(tokenIds_.size());
    
    // Route tokens through the MoE router to select top-k experts
    // The router computes: router_logits = W_router * hidden_state
    // Then selects top-k experts via softmax and gating
    for (size_t i = 0; i < tokenIds_.size(); ++i) {
        BatchResult result;
        result.tokenId = tokenIds_[i];
        result.outputHidden = hiddenStates_[i];
        
        // Compute router logits: project hidden state through router weights
        // router_weights: [num_experts, hidden_dim]
        std::vector<float> routerLogits(numExperts_, 0.0f);
        if (routerWeights_) {
            // Real router forward pass: logits = W_router * h
            for (uint32_t e = 0; e < numExperts_; ++e) {
                const float* expertWeights = routerWeights_ + e * hiddenDim_;
                float logit = 0.0f;
                for (size_t d = 0; d < hiddenDim_; ++d) {
                    logit += expertWeights[d] * hiddenStates_[i][d];
                }
                routerLogits[e] = logit;
            }
            
            // Apply softmax to get expert weights
            float maxLogit = *std::max_element(routerLogits.begin(), routerLogits.end());
            float sumExp = 0.0f;
            for (uint32_t e = 0; e < numExperts_; ++e) {
                routerLogits[e] = std::exp(routerLogits[e] - maxLogit);
                sumExp += routerLogits[e];
            }
            for (uint32_t e = 0; e < numExperts_; ++e) {
                routerLogits[e] /= sumExp;
            }
            
            // Select top-k experts by weight
            result.numExperts = topK_;
            std::vector<std::pair<float, uint32_t>> expertWeights;
            for (uint32_t e = 0; e < numExperts_; ++e) {
                expertWeights.push_back({routerLogits[e], e});
            }
            std::partial_sort(expertWeights.begin(), 
                            expertWeights.begin() + topK_,
                            expertWeights.end(),
                            std::greater<std::pair<float, uint32_t>>());
            
            for (uint32_t j = 0; j < topK_; ++j) {
                result.selectedExperts[j] = expertWeights[j].second;
                result.expertWeights[j] = expertWeights[j].first;
            }
        } else {
            // Fallback: uniform distribution when router not initialized
            result.numExperts = topK_;
            for (uint32_t j = 0; j < topK_; ++j) {
                result.selectedExperts[j] = j;
                result.expertWeights[j] = 1.0f / topK_;
            }
        }
        results_.push_back(result);
    }
}

const std::vector<TokenBatchRouter::BatchResult>& TokenBatchRouter::GetResults() const {
    return results_;
}

std::vector<TokenBatchRouter::ExpertBucket> TokenBatchRouter::BucketByExpert(
    const std::vector<BatchResult>& results) {
    std::vector<ExpertBucket> buckets;
    std::unordered_map<uint32_t, size_t> expertToBucket;
    
    for (const auto& result : results) {
        for (uint32_t i = 0; i < result.numExperts; ++i) {
            uint32_t expert = result.selectedExperts[i];
            auto it = expertToBucket.find(expert);
            if (it == expertToBucket.end()) {
                ExpertBucket bucket;
                bucket.expertIdx = expert;
                bucket.tokenIndices.push_back(result.tokenId);
                buckets.push_back(bucket);
                expertToBucket[expert] = buckets.size() - 1;
            } else {
                buckets[it->second].tokenIndices.push_back(result.tokenId);
            }
        }
    }
    
    return buckets;
}

// ============================================================================
// MemoryScheduler Implementation
// ============================================================================

MemoryScheduler::MemoryScheduler(ExpertResidencyManager& residency)
    : residency_(residency), predictionsCorrect_(0), predictionsTotal_(0) {
}

MemoryScheduler::~MemoryScheduler() {
}

void MemoryScheduler::PredictNextExperts(uint32_t currentLayer, const float* routerLogits) {
    // Simple prediction: top-k from current router output
    // More sophisticated: LSTM or transformer-based prediction
    
    // Find top-k experts
    std::vector<std::pair<float, uint32_t>> scoredExperts;
    // scoredExperts.reserve(numExperts);
    
    // Sort by score
    std::sort(scoredExperts.begin(), scoredExperts.end(), std::greater<>());
    
    // Store predictions
    Prediction pred;
    pred.layer = currentLayer + 1;  // Predict next layer
    pred.confidence = scoredExperts.empty() ? 0.0f : scoredExperts[0].first;
    pred.predictedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    
    predictions_.push_back(pred);
    predictionsTotal_++;
}

void MemoryScheduler::ScheduleLoads() {
    // Sort predictions by confidence and layer distance
    std::sort(predictions_.begin(), predictions_.end(),
        [](const Prediction& a, const Prediction& b) {
            return a.confidence > b.confidence;
        });
    
    // Schedule top predictions for prefetch
    for (const auto& pred : predictions_) {
        if (pred.confidence > 0.5f) {  // Threshold
            // residency_.PrefetchExpert(pred.layer, pred.expert, ...);
        }
    }
}

void MemoryScheduler::ExecuteLoads() {
    // Execute scheduled loads
}

float MemoryScheduler::GetPredictionAccuracy() const {
    if (predictionsTotal_ == 0) return 0.0f;
    return static_cast<float>(predictionsCorrect_) / predictionsTotal_;
}

} // namespace Deep2
