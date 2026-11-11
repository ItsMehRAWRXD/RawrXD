//==============================================================================
// KernelRegistry.cpp
// Central Registry Implementation
//
// Date: July 10, 2026
// Phase: 7C.1 - Kernel Registry Architecture
//==============================================================================

#include "KernelRegistry.hpp"
#include <algorithm>
#include <cmath>
#include <mutex>

namespace sovereign {

//======================================================================
// Singleton
//======================================================================

KernelRegistry& KernelRegistry::Instance() {
    static KernelRegistry instance;
    return instance;
}

//======================================================================
// Backend Management
//======================================================================

uint32_t KernelRegistry::RegisterBackend(std::unique_ptr<IKernelBackend> backend) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint32_t id = nextBackendId_++;
    backends_[id] = std::move(backend);
    
    return id;
}

void KernelRegistry::UnregisterBackend(uint32_t backendId) {
    std::lock_guard<std::mutex> lock(mutex_);
    backends_.erase(backendId);
}

IKernelBackend* KernelRegistry::GetBackend(uint32_t backendId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = backends_.find(backendId);
    return (it != backends_.end()) ? it->second.get() : nullptr;
}

IKernelBackend* KernelRegistry::GetBackend(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, backend] : backends_) {
        if (backend->GetInfo().name == name) {
            return backend.get();
        }
    }
    return nullptr;
}

std::vector<std::pair<uint32_t, BackendInfo>> KernelRegistry::ListBackends() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::pair<uint32_t, BackendInfo>> result;
    for (const auto& [id, backend] : backends_) {
        result.push_back({id, backend->GetInfo()});
    }
    return result;
}

bool KernelRegistry::InitializeAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    bool allSuccess = true;
    for (auto& [id, backend] : backends_) {
        if (!backend->Initialize()) {
            allSuccess = false;
        }
    }
    return allSuccess;
}

void KernelRegistry::ShutdownAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, backend] : backends_) {
        backend->Shutdown();
    }
}

//======================================================================
// Backend Selection
//======================================================================

void KernelRegistry::SetSelectionPolicy(SelectionPolicy policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    policy_ = policy;
}

SelectionPolicy KernelRegistry::GetSelectionPolicy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return policy_;
}

void KernelRegistry::SetPreferredBackend(uint32_t backendId) {
    std::lock_guard<std::mutex> lock(mutex_);
    preferredBackend_ = backendId;
    policy_ = SelectionPolicy::SPECIFIC;
}

void KernelRegistry::SetPreferredBackend(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [id, backend] : backends_) {
        if (backend->GetInfo().name == name) {
            preferredBackend_ = id;
            policy_ = SelectionPolicy::SPECIFIC;
            return;
        }
    }
}

IKernelBackend* KernelRegistry::SelectBackend(KernelId id, size_t inputSize) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    switch (policy_) {
        case SelectionPolicy::REFERENCE_ONLY:
            // Find reference backend
            for (const auto& [bid, backend] : backends_) {
                if (HasCapability(backend->GetInfo().capabilities, BackendCapability::REFERENCE)) {
                    return backend.get();
                }
            }
            return nullptr;
            
        case SelectionPolicy::SPECIFIC:
            if (preferredBackend_ != 0) {
                auto it = backends_.find(preferredBackend_);
                if (it != backends_.end() && it->second->SupportsKernel(id)) {
                    return it->second.get();
                }
            }
            return nullptr;
            
        case SelectionPolicy::FASTEST:
        case SelectionPolicy::AUTO: {
            // Use performance history to select best
            uint32_t bestBackend = GetBestBackend(id, inputSize);
            if (bestBackend != 0) {
                auto it = backends_.find(bestBackend);
                if (it != backends_.end()) {
                    return it->second.get();
                }
            }
            
            // Fallback: find first backend that supports this kernel
            for (const auto& [bid, backend] : backends_) {
                if (backend->SupportsKernel(id)) {
                    return backend.get();
                }
            }
            return nullptr;
        }
        
        case SelectionPolicy::MOST_ACCURATE:
            // Prefer reference, then intrinsics, then others
            for (const auto& [bid, backend] : backends_) {
                if (HasCapability(backend->GetInfo().capabilities, BackendCapability::REFERENCE) &&
                    backend->SupportsKernel(id)) {
                    return backend.get();
                }
            }
            // Fall through to any available
            for (const auto& [bid, backend] : backends_) {
                if (backend->SupportsKernel(id)) {
                    return backend.get();
                }
            }
            return nullptr;
    }
    
    return nullptr;
}

//======================================================================
// Unified Execution
//======================================================================

bool KernelRegistry::Execute(KernelId id,
                            const TensorDesc& input,
                            TensorDesc& output,
                            const KernelParams& params,
                            ExecutionStats* stats) {
    IKernelBackend* backend = SelectBackend(id, input.sizeBytes);
    if (!backend) {
        return false;
    }
    
    // Dispatch to appropriate method based on kernel ID
    // This is a simplified dispatch - full implementation would
    // handle all kernel types
    
    switch (id) {
        case KernelId::MatMul_Q4_Q8: {
            MatMulParams mmParams;
            // Extract from params...
            return backend->MatMul(input, input, output, mmParams, stats);
        }
        case KernelId::FlashAttentionV2: {
            AttentionParams attnParams;
            return backend->FlashAttention(input, input, input, output, attnParams, stats);
        }
        default:
            return false;
    }
}

bool KernelRegistry::ExecuteWithBackend(uint32_t backendId,
                                       KernelId id,
                                       const TensorDesc& input,
                                       TensorDesc& output,
                                       const KernelParams& params,
                                       ExecutionStats* stats) {
    IKernelBackend* backend = GetBackend(backendId);
    if (!backend || !backend->SupportsKernel(id)) {
        return false;
    }
    
    // Dispatch to appropriate method based on kernel ID
    auto start_time = std::chrono::high_resolution_clock::now();
    bool result = false;
    
    switch (id) {
        case KernelId::MatMul_Q4_Q8:
        case KernelId::MatMul_F32:
        case KernelId::MatMul_F16: {
            MatMulParams mmParams;
            mmParams.M = params.dims[0];
            mmParams.N = params.dims[1];
            mmParams.K = params.dims[2];
            mmParams.alpha = params.alpha;
            mmParams.beta = params.beta;
            result = backend->MatMul(input, input, output, mmParams, stats);
            break;
        }
        case KernelId::FlashAttentionV2:
        case KernelId::FlashAttentionV1: {
            AttentionParams attnParams;
            attnParams.batchSize = params.dims[0];
            attnParams.numHeads = params.dims[1];
            attnParams.seqLen = params.dims[2];
            attnParams.headDim = params.dims[3];
            attnParams.scale = params.scale;
            result = backend->FlashAttention(input, input, input, output, attnParams, stats);
            break;
        }
        case KernelId::RMSNorm:
        case KernelId::LayerNorm: {
            NormParams normParams;
            normParams.epsilon = params.epsilon;
            normParams.axis = params.axis;
            result = backend->RMSNorm(input, output, normParams, stats);
            break;
        }
        case KernelId::SiLU:
        case KernelId::ReLU:
        case KernelId::GELU: {
            ActivationParams actParams;
            actParams.type = params.activationType;
            result = backend->Activation(input, output, actParams, stats);
            break;
        }
        case KernelId::Softmax: {
            SoftmaxParams smParams;
            smParams.axis = params.axis;
            smParams.temperature = params.temperature;
            result = backend->Softmax(input, output, smParams, stats);
            break;
        }
        case KernelId::RoPE: {
            RoPEParams ropeParams;
            ropeParams.seqLen = params.dims[0];
            ropeParams.headDim = params.dims[1];
            ropeParams.base = params.ropeBase;
            result = backend->RoPE(input, output, ropeParams, stats);
            break;
        }
        default:
            // Try generic dispatch
            result = backend->ExecuteGeneric(id, input, output, params, stats);
            break;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    if (stats) {
        stats->executionTimeUs = duration.count();
        stats->gflops = CalculateGFLOPs(id, input.sizeBytes, duration.count());
    }
    
    // Record performance for backend selection
    if (result) {
        PerformanceEntry entry;
        entry.kernel = id;
        entry.backendId = backendId;
        entry.inputSize = input.sizeBytes;
        entry.executionTimeUs = duration.count();
        entry.timestamp = std::chrono::system_clock::now();
        RecordPerformance(entry);
    }
    
    return result;
}

//======================================================================
// Performance Tracking
//======================================================================

void KernelRegistry::RecordPerformance(const PerformanceEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    performanceHistory_.push_back(entry);
    
    // Limit history size
    if (performanceHistory_.size() > 10000) {
        performanceHistory_.erase(performanceHistory_.begin());
    }
}

std::vector<PerformanceEntry> KernelRegistry::GetPerformanceHistory(KernelId id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PerformanceEntry> result;
    for (const auto& entry : performanceHistory_) {
        if (entry.kernel == id) {
            result.push_back(entry);
        }
    }
    return result;
}

uint32_t KernelRegistry::GetBestBackend(KernelId id, size_t inputSize) const {
    // Find backend with best average performance for this kernel
    std::map<uint32_t, std::vector<double>> backendTimes;
    
    for (const auto& entry : performanceHistory_) {
        if (entry.kernel == id && 
            std::abs((double)entry.inputSize - (double)inputSize) < inputSize * 0.1) {
            backendTimes[entry.backendId].push_back((double)entry.executionTimeUs);
        }
    }
    
    uint32_t bestBackend = 0;
    double bestAvgTime = std::numeric_limits<double>::max();
    
    for (const auto& [bid, times] : backendTimes) {
        if (times.empty()) continue;
        double avg = 0.0;
        for (double t : times) avg += t;
        avg /= times.size();
        
        if (avg < bestAvgTime) {
            bestAvgTime = avg;
            bestBackend = bid;
        }
    }
    
    return bestBackend;
}

void KernelRegistry::ClearPerformanceHistory() {
    std::lock_guard<std::mutex> lock(mutex_);
    performanceHistory_.clear();
}

//======================================================================
// Validation & Comparison
//======================================================================

std::vector<KernelRegistry::ComparisonResult> KernelRegistry::CompareBackends(
    KernelId id,
    const TensorDesc& input,
    const TensorDesc& expectedOutput,
    const KernelParams& params) {
    
    std::vector<ComparisonResult> results;
    
    // Get reference output first using first available backend
    TensorDesc referenceOutput = expectedOutput;
    bool hasReference = false;
    
    for (const auto& [bid, backend] : backends_) {
        if (!backend->SupportsKernel(id)) continue;
        
        ExecutionStats stats;
        if (ExecuteWithBackend(bid, id, input, referenceOutput, params, &stats)) {
            hasReference = true;
            break;
        }
    }
    
    if (!hasReference) {
        // No backend can execute this kernel
        return results;
    }
    
    // Test each backend against reference
    for (const auto& [bid, backend] : backends_) {
        if (!backend->SupportsKernel(id)) continue;
        
        ComparisonResult result;
        result.backendId = bid;
        result.backendName = backend->GetInfo().name;
        
        // Execute
        TensorDesc actualOutput = expectedOutput;
        ExecutionStats stats;
        
        result.success = ExecuteWithBackend(bid, id, input, actualOutput, params, &stats);
        
        if (result.success) {
            result.executionTimeUs = stats.executionTimeUs;
            result.gflops = stats.gflops;
            
            // Calculate error vs reference
            result.maxError = 0.0;
            result.meanError = 0.0;
            
            if (actualOutput.data && referenceOutput.data && 
                actualOutput.sizeBytes == referenceOutput.sizeBytes) {
                
                size_t numElements = actualOutput.sizeBytes / sizeof(float);
                const float* actual = static_cast<const float*>(actualOutput.data);
                const float* ref = static_cast<const float*>(referenceOutput.data);
                
                double totalError = 0.0;
                for (size_t i = 0; i < numElements; i++) {
                    double error = std::abs(actual[i] - ref[i]);
                    result.maxError = std::max(result.maxError, error);
                    totalError += error;
                }
                result.meanError = totalError / numElements;
            }
        }
        
        results.push_back(result);
    }
    
    return results;
}

bool KernelRegistry::ValidateBackend(uint32_t backendId, KernelId id, 
                                    double maxErrorTolerance) {
    // Run comparison and check errors
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto backendIt = backends_.find(backendId);
    if (backendIt == backends_.end() || !backendIt->second->SupportsKernel(id)) {
        return false;
    }
    
    // Find reference backend (prefer CPU/reference implementations)
    uint32_t refBackendId = 0;
    for (const auto& [bid, backend] : backends_) {
        if (backend->GetInfo().type == BackendType::Reference) {
            refBackendId = bid;
            break;
        }
    }
    
    if (refBackendId == 0 || refBackendId == backendId) {
        // No reference available or testing against self
        return true;
    }
    
    // Create test input
    TensorDesc testInput;
    testInput.sizeBytes = 1024 * sizeof(float);  // 1K elements
    testInput.data = malloc(testInput.sizeBytes);
    if (!testInput.data) return false;
    
    // Fill with test pattern
    float* data = static_cast<float*>(testInput.data);
    for (size_t i = 0; i < 1024; i++) {
        data[i] = static_cast<float>(i) * 0.01f;
    }
    
    TensorDesc refOutput;
    refOutput.sizeBytes = testInput.sizeBytes;
    refOutput.data = malloc(refOutput.sizeBytes);
    
    TensorDesc testOutput;
    testOutput.sizeBytes = testInput.sizeBytes;
    testOutput.data = malloc(testOutput.sizeBytes);
    
    bool valid = false;
    if (refOutput.data && testOutput.data) {
        KernelParams params;
        memset(&params, 0, sizeof(params));
        
        // Get reference output
        if (ExecuteWithBackend(refBackendId, id, testInput, refOutput, params, nullptr)) {
            // Get test output
            if (ExecuteWithBackend(backendId, id, testInput, testOutput, params, nullptr)) {
                // Compare
                float* ref = static_cast<float*>(refOutput.data);
                float* test = static_cast<float*>(testOutput.data);
                
                valid = true;
                for (size_t i = 0; i < 1024 && valid; i++) {
                    double error = std::abs(test[i] - ref[i]);
                    if (error > maxErrorTolerance) {
                        valid = false;
                    }
                }
            }
        }
    }
    
    free(testInput.data);
    free(refOutput.data);
    free(testOutput.data);
    
    return valid;
}

//======================================================================
// Convenience Functions
//======================================================================

bool InitializeDefaultBackends() {
    KernelRegistry& registry = KernelRegistry::Instance();
    
    // Register Reference backend (always available)
    extern IKernelBackend* CreateReferenceBackend();
    registry.RegisterBackend(std::unique_ptr<IKernelBackend>(CreateReferenceBackend()));
    
    // Register Intrinsics backend (if available)
    extern IKernelBackend* CreateIntrinsicsBackend();
    auto intrinsics = std::unique_ptr<IKernelBackend>(CreateIntrinsicsBackend());
    if (intrinsics->Initialize()) {
        registry.RegisterBackend(std::move(intrinsics));
    }
    
    return true;
}

bool ExecuteKernel(KernelId id,
                  const TensorDesc& input,
                  TensorDesc& output,
                  const KernelParams& params) {
    return KernelRegistry::Instance().Execute(id, input, output, params, nullptr);
}

} // namespace sovereign
