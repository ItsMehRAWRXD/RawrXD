// ============================================================================
// Sovereign Backend
// ============================================================================
// Production backend that dispatches to MASM64 kernels via execution contracts
// Bridges ExecutionRequest → Sovereign kernel dispatch
// ============================================================================

#pragma once

#include "IExecutionBackend.hpp"
#include "ExecutionRequest.hpp"
#include "ExecutionResult.hpp"
#include "ExecutionTelemetry.hpp"
#include "MASM64KernelLoader.hpp"

#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <atomic>

namespace RawrXD {
namespace Execution {

// ============================================================================
// Sovereign Kernel Handle
// ============================================================================
// Opaque handle to loaded MASM64 kernel
// ============================================================================

struct SovereignKernel {
    std::string name;
    void* entry_point = nullptr;      // MASM64 function pointer
    void* data_buffer = nullptr;      // Kernel-local data
    size_t data_size = 0;
    bool loaded = false;
    
    // Performance tracking
    uint64_t invocation_count = 0;
    uint64_t total_cycles = 0;
};

// ============================================================================
// Kernel Load Configuration
// ============================================================================

struct SovereignBackendConfig {
    // Kernel library path
    std::string kernel_library_path = "d:\\src\\asm\\Sovereign_KernelLibrary.obj";
    
    // Execution mode
    bool use_avx512 = true;
    bool use_vulkan = false;  // Future: GPU dispatch
    bool deterministic_mode = false;
    
    // Threading
    uint32_t num_threads = 0;  // 0 = auto-detect
    
    // Memory
    size_t workspace_size = 256 * 1024 * 1024;  // 256MB workspace
    
    // Telemetry
    bool enable_profiling = true;
    bool enable_telemetry = true;
};

// ============================================================================
// Sovereign Backend Implementation
// ============================================================================

class SovereignBackend : public IExecutionBackend {
public:
    explicit SovereignBackend(const SovereignBackendConfig& config = SovereignBackendConfig{});
    ~SovereignBackend() override;
    
    // IExecutionBackend implementation
    const char* GetName() const override { return "sovereign"; }
    const char* GetVersion() const override { return "1.0.0-masm64"; }
    
    bool Initialize() override;
    void Shutdown() override;
    bool IsInitialized() const override { return initialized_; }
    
    bool SupportsModel(const std::string& model_path) const override;
    bool SupportsStreaming() const override { return true; }
    bool SupportsCancellation() const override { return true; }
    
    ExecutionResult Execute(const ExecutionRequest& request) override;
    bool ExecuteAsync(const ExecutionRequest& request,
                     TokenCallback on_token,
                     CompletionCallback on_complete) override;
    
    void Cancel() override;
    bool IsHealthy() const override;
    
    // Sovereign-specific API
    bool LoadKernel(const std::string& kernel_name);
    bool UnloadKernel(const std::string& kernel_name);
    bool IsKernelLoaded(const std::string& kernel_name) const;
    
    // Direct kernel invocation (for GraphRunner)
    ExecutionResult InvokeKernel(const std::string& kernel_name,
                                  const void* input_data,
                                  size_t input_size,
                                  void* output_data,
                                  size_t output_size);
    
    // Kernel registry
    std::vector<std::string> GetLoadedKernels() const;
    const SovereignKernel* GetKernelInfo(const std::string& name) const;
    
    // Workspace management
    void* GetWorkspace(size_t size);
    void ReleaseWorkspace(void* ptr);
    
    // Configuration
    const SovereignBackendConfig& GetConfig() const { return config_; }
    void SetConfig(const SovereignBackendConfig& config);

private:
    SovereignBackendConfig config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> cancelled_{false};
    
    // Kernel registry
    std::unordered_map<std::string, SovereignKernel> kernels_;
    
    // MASM64 kernel loader
    std::unique_ptr<MASM64KernelLoader> kernel_loader_;
    
    // Workspace memory
    void* workspace_ = nullptr;
    size_t workspace_used_ = 0;
    
    // Telemetry
    ExecutionTelemetry last_telemetry_;
    
    // Internal helpers
    bool InitializeWorkspace();
    void CleanupWorkspace();
    bool LoadKernelsFromObjectFile(const std::string& filepath);
    
    ExecutionResult ExecuteEmbedding(const ExecutionRequest& request);
    ExecutionResult ExecuteRMSNorm(const ExecutionRequest& request);
    ExecutionResult ExecuteAttention(const ExecutionRequest& request);
    ExecutionResult ExecuteFFN(const ExecutionRequest& request);
    ExecutionResult ExecuteSampling(const ExecutionRequest& request);
    ExecutionResult ExecuteQKVProjection(const ExecutionRequest& request);
    ExecutionResult ExecuteRoPE(const ExecutionRequest& request);
    ExecutionResult ExecuteAttentionOutput(const ExecutionRequest& request);
    
    // MASM64 kernel dispatch (platform-specific)
    typedef void (*KernelFunc)(void* input, void* output, size_t count);
    bool DispatchMASM64(const SovereignKernel& kernel,
                       const void* input,
                       void* output,
                       size_t count);
    
    // Telemetry helpers
    void RecordTelemetry(const ExecutionTelemetry& telemetry);
};

// ============================================================================
// Factory Function
// ============================================================================

std::unique_ptr<SovereignBackend> CreateSovereignBackend(
    const SovereignBackendConfig& config = SovereignBackendConfig{});

} // namespace Execution
} // namespace RawrXD
