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
    
    // Similar dispatch as Execute...
    return false; // Placeholder
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
    
    // Get reference output first
    TensorDesc referenceOutput = expectedOutput;
    
    for (const auto& [bid, backend] : backends_) {
        if (!backend->SupportsKernel(id)) continue;
        
        ComparisonResult result;
        result.backendId = bid;
        result.backendName = backend->GetInfo().name;
        
        // Execute
        TensorDesc actualOutput = expectedOutput;
        ExecutionStats stats;
        
        // Dispatch based on kernel type...
        result.success = false; // Placeholder
        
        if (result.success) {
            result.executionTimeUs = stats.executionTimeUs;
            result.gflops = stats.gflops;
            
            // Calculate error vs reference
            // ...
        }
        
        results.push_back(result);
    }
    
    return results;
}

bool KernelRegistry::ValidateBackend(uint32_t backendId, KernelId id, 
                                    double maxErrorTolerance) {
    // Run comparison and check errors
    return false; // Placeholder
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
