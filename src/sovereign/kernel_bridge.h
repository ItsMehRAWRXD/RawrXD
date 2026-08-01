// kernel_bridge.h
// RawrXD Kernel Bridge v1.0
// Direct bridge between ExecutionSpine and KernelDispatcher
// Zero-copy buffer mapping for maximum compute density

#ifndef KERNEL_BRIDGE_H
#define KERNEL_BRIDGE_H

#include "execution_contract.h"
#include <cstdint>
#include <vector>
#include <memory>
#include <functional>

// Forward declarations for kernel subsystem
namespace RawrXD {
    class KernelDispatcher;
    struct KernelBuffer;
    struct KernelConfig;
}

namespace sovereign {

// ============================================================
// KERNEL BRIDGE - Spine-to-Metal Adapter
// ============================================================

class KernelBridge {
public:
    // Performance metrics from kernel execution
    struct KernelMetrics {
        double gflops = 0.0;
        double tokens_per_ms = 0.0;
        double memory_bandwidth_gbps = 0.0;
        uint64_t cycles_elapsed = 0;
        uint64_t cache_misses = 0;
        uint64_t instructions_retired = 0;
        
        // Per-kernel timing breakdown
        struct KernelTiming {
            std::string kernel_name;
            double duration_ms = 0.0;
            double utilization_percent = 0.0;
        };
        std::vector<KernelTiming> kernel_timings;
        
        std::string to_json() const;
    };
    
    // Buffer descriptor for zero-copy operations
    struct BufferDesc {
        void* data = nullptr;
        size_t size_bytes = 0;
        size_t alignment = 64;  // AVX-512 alignment
        uint32_t flags = 0;
        
        enum Flags {
            HOST_VISIBLE = 1 << 0,
            DEVICE_LOCAL = 1 << 1,
            PINNED = 1 << 2,
            WRITE_COMBINED = 1 << 3
        };
    };
    
    // Kernel execution configuration
    struct ExecutionConfig {
        uint32_t batch_size = 1;
        uint32_t seq_length = 1;
        uint32_t hidden_dim = 4096;
        uint32_t num_heads = 32;
        uint32_t head_dim = 128;
        uint32_t vocab_size = 32000;
        
        // Backend selection
        enum class Backend {
            AUTO,       // Let dispatcher decide
            SCALAR,     // Fallback C++
            AVX2,       // 256-bit vectors
            AVX512,     // 512-bit vectors
            VULKAN,     // GPU compute
            MASM_OPTIMAL // Hand-tuned assembly
        };
        Backend backend = Backend::AUTO;
        
        // Performance tuning
        bool enable_profiling = true;
        bool async_execution = false;
        uint32_t thread_count = 0;  // 0 = auto
    };

    KernelBridge();
    ~KernelBridge();
    
    // Initialize bridge with execution context
    bool Initialize(const ExecutionConfig& config);
    void Shutdown();
    
    // Core execution interface
    bool ExecuteInference(const ExecutionRequest& request,
                          const std::vector<uint32_t>& input_tokens,
                          std::vector<float>& output_logits,
                          KernelMetrics& out_metrics);
    
    // Direct kernel dispatch (bypasses high-level inference)
    bool DispatchMatMul(const BufferDesc& A,
                        const BufferDesc& B,
                        BufferDesc& C,
                        uint32_t M, uint32_t N, uint32_t K,
                        KernelMetrics& out_metrics);
    
    bool DispatchAttention(const BufferDesc& Q,
                           const BufferDesc& K,
                           const BufferDesc& V,
                           BufferDesc& output,
                           uint32_t batch, uint32_t seq_len, uint32_t heads, uint32_t head_dim,
                           KernelMetrics& out_metrics);
    
    // MASM kernel registration
    bool RegisterMASMKernel(const std::string& name,
                            void* func_ptr,
                            const std::vector<size_t>& param_sizes);
    
    // Performance profiling
    KernelMetrics GetLastMetrics() const { return last_metrics_; }
    std::vector<std::string> GetAvailableKernels() const;
    
    // Buffer management
    BufferDesc AllocateBuffer(size_t size_bytes, uint32_t flags = BufferDesc::HOST_VISIBLE);
    void FreeBuffer(BufferDesc& buffer);
    bool CopyBuffer(const BufferDesc& src, BufferDesc& dst, size_t size_bytes);
    
    // Verification
    bool VerifyKernelOutput(const BufferDesc& output,
                            const std::string& expected_hash,
                            std::string& actual_hash);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    KernelMetrics last_metrics_;
    ExecutionConfig current_config_;
    bool initialized_ = false;
};

// ============================================================
// KERNEL PROFILER - Real-time performance telemetry
// ============================================================

class KernelProfiler {
public:
    struct ProfileSample {
        uint64_t timestamp_ns;
        std::string kernel_name;
        double duration_ms;
        double gflops;
        size_t memory_bytes;
    };
    
    void BeginSample(const std::string& kernel_name);
    void EndSample(size_t flops_executed = 0, size_t memory_bytes = 0);
    
    std::vector<ProfileSample> GetSamples() const;
    void ClearSamples();
    
    // Aggregate statistics
    struct AggregateStats {
        double mean_latency_ms = 0.0;
        double p99_latency_ms = 0.0;
        double mean_gflops = 0.0;
        double peak_gflops = 0.0;
        uint64_t total_samples = 0;
    };
    AggregateStats ComputeStats() const;
    
private:
    std::vector<ProfileSample> samples_;
    uint64_t current_sample_start_ = 0;
    std::string current_kernel_;
};

// ============================================================
// KERNEL CERTIFICATION - Verify assembly correctness
// ============================================================

class KernelCertifier {
public:
    struct CertificationResult {
        bool passed = false;
        std::string kernel_name;
        std::vector<std::string> checks_passed;
        std::vector<std::string> checks_failed;
        double max_error = 0.0;
        double mean_error = 0.0;
    };
    
    // Verify kernel output against reference implementation
    CertificationResult CertifyKernel(const std::string& kernel_name,
                                       const KernelBridge::BufferDesc& output,
                                       const KernelBridge::BufferDesc& reference);
    
    // Run full certification suite
    std::vector<CertificationResult> RunCertificationSuite();
    
    // Generate certification report
    std::string GenerateReport(const std::vector<CertificationResult>& results);
};

} // namespace sovereign

#endif // KERNEL_BRIDGE_H
