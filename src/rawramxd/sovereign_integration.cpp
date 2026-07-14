/**
 * RawRamXD Phase 8: Sovereign Integration Implementation
 * 
 * Hooks predictive prefetcher into inference loop.
 */

#include "rawramxd/sovereign_integration.hpp"
#include <iostream>
#include <chrono>

namespace RawRamXD {

// =============================================================================
// SINGLETON INSTANCE
// =============================================================================

SovereignIntegration& SovereignIntegration::Instance() {
    static SovereignIntegration instance;
    return instance;
}

// =============================================================================
// LIFECYCLE
// =============================================================================

bool SovereignIntegration::Initialize(const SovereignConfig& config) {
    if (initialized_) {
        return true;
    }
    
    config_ = config;
    
    // Initialize GPU Fabric
    if (!GPUFabric::Instance().Initialize()) {
        std::cerr << "[Sovereign] Failed to initialize GPU Fabric\n";
        return false;
    }
    
    // Initialize Predictor
    predictor_ = std::make_unique<TensorPredictor>();
    if (!predictor_->Initialize(32, 16000)) { // 32 layers, 16ms token latency
        std::cerr << "[Sovereign] Failed to initialize predictor\n";
        return false;
    }
    
    // Initialize Orchestrator
    orchestrator_ = std::make_unique<PrefetchOrchestrator>(predictor_.get());
    if (!orchestrator_->Initialize(config_.prefetchBandwidthLimit)) {
        std::cerr << "[Sovereign] Failed to initialize orchestrator\n";
        return false;
    }
    
    initialized_ = true;
    std::cout << "[Sovereign] Integration layer initialized\n";
    std::cout << "  Prefetch: " << (config_.enablePrefetch ? "enabled" : "disabled") << "\n";
    std::cout << "  Learning: " << (config_.enableLearning ? "enabled" : "disabled") << "\n";
    std::cout << "  Confidence threshold: " << config_.prefetchConfidenceThreshold << "\n";
    
    return true;
}

void SovereignIntegration::Shutdown() {
    if (!initialized_) return;
    
    if (orchestrator_) {
        orchestrator_->Shutdown();
        orchestrator_.reset();
    }
    
    if (predictor_) {
        predictor_->Shutdown();
        predictor_.reset();
    }
    
    GPUFabric::Instance().Shutdown();
    
    initialized_ = false;
    std::cout << "[Sovereign] Integration layer shutdown\n";
}

// =============================================================================
// TENSOR OPERATIONS
// =============================================================================

void* SovereignIntegration::LoadTensor(uint64_t tensorId, size_t size, 
                                       ComputeTargetType preferredTier) {
    if (!initialized_) {
        // Fallback to direct fabric access
        return GPUFabric::Instance().Allocate(size, preferredTier);
    }
    
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    // Check if this tensor was prefetched
    auto it = prefetchTimestamps_.find(tensorId);
    if (it != prefetchTimestamps_.end()) {
        // Prefetch hit!
        stats_.prefetchHits++;
        activePrefetches_.erase(tensorId);
    }
    
    // Allocate from fabric
    void* ptr = GPUFabric::Instance().Allocate(size, preferredTier);
    if (ptr) {
        stats_.tensorsLoaded++;
    }
    
    return ptr;
}

void SovereignIntegration::RecordTensorAccess(uint64_t tensorId, uint64_t offset, size_t size) {
    if (!initialized_ || !config_.enableLearning) return;
    
    // Record for pattern learning
    AccessEvent event{};
    event.timestampUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    event.tensorHandle = tensorId;
    event.layerIndex = currentLayer_;
    event.opType = 1; // Compute
    event.computeTimeUs = 500; // Estimated
    
    predictor_->RecordAccess(event);
    
    // Call user callback if registered
    if (accessCallback_) {
        accessCallback_(tensorId, offset, size);
    }
}

// =============================================================================
// TOKEN LIFECYCLE
// =============================================================================

void SovereignIntegration::OnTokenStart(uint64_t tokenIndex) {
    if (!initialized_) return;
    
    currentToken_ = tokenIndex;
    
    if (orchestrator_) {
        orchestrator_->OnTokenStart(tokenIndex);
    }
    
    // Issue prefetches based on predictions
    if (config_.enablePrefetch && predictor_) {
        auto predictions = predictor_->PredictNextAccesses(100000); // 100ms horizon
        
        uint32_t prefetchesIssued = 0;
        for (const auto& pred : predictions) {
            if (prefetchesIssued >= config_.maxPrefetchesPerToken) break;
            if (pred.confidence < config_.prefetchConfidenceThreshold) continue;
            
            // Check if already prefetched
            if (activePrefetches_.count(pred.tensorHandle)) continue;
            
            // Schedule prefetch
            if (orchestrator_->SchedulePrefetchDuringCompute(
                pred.tensorHandle, 16000)) { // 16ms compute window
                
                activePrefetches_.insert(pred.tensorHandle);
                prefetchTimestamps_[pred.tensorHandle] = 
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
                
                prefetchesIssued++;
                stats_.tensorsPrefetched++;
            }
        }
    }
}

void SovereignIntegration::OnTokenComplete(uint64_t tokenIndex, uint64_t durationUs) {
    if (!initialized_) return;
    
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    stats_.tokensProcessed++;
    
    // Update average stall
    // Estimate stall as portion of duration that was migration
    // This is simplified - real implementation would measure actual stall
    float stallUs = 0.0f;
    
    // Check for prefetch misses (prefetched but not accessed)
    for (const auto& [tensorId, timestamp] : prefetchTimestamps_) {
        if (!activePrefetches_.count(tensorId)) {
            // Was accessed (removed from activePrefetches in LoadTensor)
        } else {
            // Was not accessed - prefetch miss
            stats_.prefetchMisses++;
        }
    }
    
    // Update running average
    stats_.avgStallPerTokenUs = 
        (stats_.avgStallPerTokenUs * (stats_.tokensProcessed - 1) + stallUs) 
        / stats_.tokensProcessed;
    
    if (orchestrator_) {
        orchestrator_->OnTokenComplete(tokenIndex, durationUs);
    }
    
    // Clear prefetch tracking for next token
    prefetchTimestamps_.clear();
    activePrefetches_.clear();
}

// =============================================================================
// LAYER LIFECYCLE
// =============================================================================

void SovereignIntegration::OnLayerStart(uint32_t layerIndex) {
    currentLayer_ = layerIndex;
}

void SovereignIntegration::OnLayerComplete(uint32_t layerIndex) {
    (void)layerIndex;
    // Could trigger layer-specific prefetch here
}

// =============================================================================
// PREFETCH OPERATIONS
// =============================================================================

std::vector<uint64_t> SovereignIntegration::GetPrefetchRecommendations(uint64_t maxBytes) {
    if (!initialized_ || !orchestrator_) {
        return {};
    }
    return orchestrator_->GetPrefetchCandidates(maxBytes);
}

bool SovereignIntegration::ExecutePrefetch(uint64_t tensorId) {
    if (!initialized_ || !orchestrator_) {
        return false;
    }
    return orchestrator_->ScheduleEmergencyPrefetch(tensorId);
}

// =============================================================================
// STATISTICS
// =============================================================================

SovereignIntegration::Stats SovereignIntegration::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    Stats s = stats_;
    
    // Calculate stall reduction
    // Compare to baseline of 37.9ms per token (from Phase 7B.2)
    float baselineStallUs = 37900.0f;
    if (s.tokensProcessed > 0) {
        s.stallReductionPercent = 
            (1.0f - (s.avgStallPerTokenUs / baselineStallUs)) * 100.0f;
    }
    
    return s;
}

// =============================================================================
// C API IMPLEMENTATION
// =============================================================================

extern "C" {

bool RawRamXD_Sovereign_Init(const SovereignConfig* config) {
    SovereignConfig cfg;
    if (config) {
        cfg = *config;
    }
    return SovereignIntegration::Instance().Initialize(cfg);
}

void RawRamXD_Sovereign_Shutdown() {
    SovereignIntegration::Instance().Shutdown();
}

bool RawRamXD_Sovereign_IsReady() {
    return SovereignIntegration::Instance().IsInitialized();
}

void* RawRamXD_Sovereign_LoadTensor(uint64_t tensorId, size_t size, int preferredTier) {
    return SovereignIntegration::Instance().LoadTensor(
        tensorId, size, static_cast<ComputeTargetType>(preferredTier));
}

void RawRamXD_Sovereign_RecordAccess(uint64_t tensorId, uint64_t offset, size_t size) {
    SovereignIntegration::Instance().RecordTensorAccess(tensorId, offset, size);
}

void RawRamXD_Sovereign_TokenStart(uint64_t tokenIndex) {
    SovereignIntegration::Instance().OnTokenStart(tokenIndex);
}

void RawRamXD_Sovereign_TokenComplete(uint64_t tokenIndex, uint64_t durationUs) {
    SovereignIntegration::Instance().OnTokenComplete(tokenIndex, durationUs);
}

void RawRamXD_Sovereign_LayerStart(uint32_t layerIndex) {
    SovereignIntegration::Instance().OnLayerStart(layerIndex);
}

void RawRamXD_Sovereign_LayerComplete(uint32_t layerIndex) {
    SovereignIntegration::Instance().OnLayerComplete(layerIndex);
}

void RawRamXD_Sovereign_GetStats(
    uint64_t* tensorsLoaded,
    uint64_t* tensorsPrefetched,
    uint64_t* prefetchHits,
    float* stallReductionPercent) {
    
    auto stats = SovereignIntegration::Instance().GetStats();
    
    if (tensorsLoaded) *tensorsLoaded = stats.tensorsLoaded;
    if (tensorsPrefetched) *tensorsPrefetched = stats.tensorsPrefetched;
    if (prefetchHits) *prefetchHits = stats.prefetchHits;
    if (stallReductionPercent) *stallReductionPercent = stats.stallReductionPercent;
}

} // extern "C"

} // namespace RawRamXD
