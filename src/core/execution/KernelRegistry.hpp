//==============================================================================
// KernelRegistry.hpp
// Central Registry for Kernel Backends
//
// Manages multiple backends (Reference, Intrinsics, MASM, GPU) and selects
// the optimal implementation based on:
// - Hardware capabilities
// - Kernel size
// - Performance history
// - Numerical precision requirements
//
// Date: July 10, 2026
// Phase: 7C.1 - Kernel Registry Architecture
//==============================================================================

#pragma once

#include "IKernelBackend.hpp"
#include <memory>
#include <vector>
#include <map>
#include <string>
#include <mutex>

namespace sovereign {

//==============================================================================
// Backend Selection Policy
//==============================================================================
enum class SelectionPolicy {
    AUTO,           // Automatic based on performance history
    REFERENCE_ONLY, // Always use reference (for validation)
    FASTEST,        // Always use fastest available
    MOST_ACCURATE, // Prioritize numerical accuracy
    SPECIFIC        // Use specific backend by name
};

//==============================================================================
// Performance History Entry
//==============================================================================
struct PerformanceEntry {
    KernelId kernel;
    uint32_t backendId;
    size_t inputSize;
    uint64_t executionTimeUs;
    double gflops;
    double maxError;
    double rmsError;
    uint64_t timestamp;
};

//==============================================================================
// Kernel Registry
//
// Singleton registry that manages all kernel backends.
// Provides unified interface for kernel execution with automatic
// backend selection.
//==============================================================================
class KernelRegistry {
public:
    // Singleton access
    static KernelRegistry& Instance();
    
    //======================================================================
    // Backend Management
    //======================================================================
    
    // Register a backend. Returns backend ID.
    uint32_t RegisterBackend(std::unique_ptr<IKernelBackend> backend);
    
    // Unregister a backend
    void UnregisterBackend(uint32_t backendId);
    
    // Get backend by ID
    IKernelBackend* GetBackend(uint32_t backendId);
    
    // Get backend by name
    IKernelBackend* GetBackend(const std::string& name);
    
    // List all registered backends
    std::vector<std::pair<uint32_t, BackendInfo>> ListBackends() const;
    
    // Initialize all backends
    bool InitializeAll();
    
    // Shutdown all backends
    void ShutdownAll();
    
    //======================================================================
    // Backend Selection
    //======================================================================
    
    // Set selection policy
    void SetSelectionPolicy(SelectionPolicy policy);
    SelectionPolicy GetSelectionPolicy() const;
    
    // Set specific backend (for SPECIFIC policy)
    void SetPreferredBackend(uint32_t backendId);
    void SetPreferredBackend(const std::string& name);
    
    // Get best backend for a kernel
    IKernelBackend* SelectBackend(KernelId id, size_t inputSize);
    
    //======================================================================
    // Unified Kernel Execution
    //======================================================================
    
    // Execute kernel with automatic backend selection
    bool Execute(KernelId id,
                 const TensorDesc& input,
                 TensorDesc& output,
                 const KernelParams& params,
                 ExecutionStats* stats = nullptr);
    
    // Execute with specific backend
    bool ExecuteWithBackend(uint32_t backendId,
                           KernelId id,
                           const TensorDesc& input,
                           TensorDesc& output,
                           const KernelParams& params,
                           ExecutionStats* stats = nullptr);
    
    //======================================================================
    // Performance Tracking
    //======================================================================
    
    // Record performance measurement
    void RecordPerformance(const PerformanceEntry& entry);
    
    // Get performance history for a kernel
    std::vector<PerformanceEntry> GetPerformanceHistory(KernelId id) const;
    
    // Get best backend for kernel based on history
    uint32_t GetBestBackend(KernelId id, size_t inputSize) const;
    
    // Clear performance history
    void ClearPerformanceHistory();
    
    //======================================================================
    // Validation & Comparison
    //======================================================================
    
    // Compare all backends for a kernel
    struct ComparisonResult {
        uint32_t backendId;
        std::string backendName;
        bool success;
        uint64_t executionTimeUs;
        double gflops;
        double maxError;
        double rmsError;
    };
    
    std::vector<ComparisonResult> CompareBackends(
        KernelId id,
        const TensorDesc& input,
        const TensorDesc& expectedOutput,
        const KernelParams& params
    );
    
    // Validate backend against reference
    bool ValidateBackend(uint32_t backendId, KernelId id, 
                        double maxErrorTolerance = 1e-4);

private:
    KernelRegistry() = default;
    ~KernelRegistry() = default;
    KernelRegistry(const KernelRegistry&) = delete;
    KernelRegistry& operator=(const KernelRegistry&) = delete;
    
    std::map<uint32_t, std::unique_ptr<IKernelBackend>> backends_;
    uint32_t nextBackendId_ = 1;
    
    SelectionPolicy policy_ = SelectionPolicy::AUTO;
    uint32_t preferredBackend_ = 0;
    
    std::vector<PerformanceEntry> performanceHistory_;
    mutable std::mutex mutex_;
};

//==============================================================================
// Convenience Functions
//==============================================================================

// Initialize registry with default backends (Reference + Intrinsics)
bool InitializeDefaultBackends();

// Quick execute - one-liner for common case
bool ExecuteKernel(KernelId id,
                  const TensorDesc& input,
                  TensorDesc& output,
                  const KernelParams& params);

} // namespace sovereign
