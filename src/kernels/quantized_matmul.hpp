/*===========================================================================
 * quantized_matmul.hpp
 *
 * C++ API for Fused Q4_0 Quantized Matrix Multiplication
 * RawrXD Fix #4 - Hybrid Static/Dynamic Dispatch
 *
 * Usage:
 *   auto kernel = KernelRegistry::Instance().Resolve(4096, 4096);
 *   kernel->Execute(weights, activation, output, N, K);
 *===========================================================================*/

#pragma once

#include <cstdint>
#include <cstddef>
#include <functional>
#include <unordered_map>
#include <memory>
#include <mutex>

namespace RawrXD {
namespace Kernels {

/*===========================================================================
 * Forward Declarations (MASM symbols)
 *===========================================================================*/
extern "C" {
    // Hot path kernels
    int QuantizedMatMul_Fused_4K(void* weights, void* activation, void* output, uint64_t N, uint64_t K);
    int QuantizedMatMul_Fused_4K_AVX512(void* weights, void* activation, void* output, uint64_t N, uint64_t K);
    int QuantizedMatMul_Fused_5K(void* weights, void* activation, void* output, uint64_t N, uint64_t K);
    int QuantizedMatMul_4Way_4K(void* weights, void* activation, void* output, uint64_t N, uint64_t K);

    // Cold path kernel
    int QuantizedMatMul_Dynamic(void* weights, void* activation, void* output, uint64_t N, uint64_t K);
    
    // Dispatch function
    int RawrXD_QuantizedMatMul_Dispatch(void* weights, void* activation, void* output, uint64_t N, uint64_t K);
    
    // Registry initialization
    int RawrXD_KernelRegistry_Init(void);
    
    // Telemetry
    uint64_t RawrXD_KernelTelemetry_Begin(void);
    uint64_t RawrXD_KernelTelemetry_End(void);
}

/*===========================================================================
 * Kernel Descriptor
 *===========================================================================*/
struct KernelDescriptor {
    uint64_t N;                    // Output dimension
    uint64_t K;                    // Input dimension
    const char* name;              // Human-readable name
    void* functionPtr;             // MASM entry point
    bool isOptimized;              // True for static unrolled kernels
    
    bool Matches(uint64_t n, uint64_t k) const {
        return N == n && K == k;
    }
};

/*===========================================================================
 * Quantized Matrix Multiplication Kernel Interface
 *===========================================================================*/
class IQuantizedMatMulKernel {
public:
    virtual ~IQuantizedMatMulKernel() = default;
    
    // Execute kernel
    // weights: Q4_0 quantized weights (packed)
    // activation: f32 activation vector (contiguous)
    // output: f32 output accumulator
    // N: output dimension
    // K: input dimension
    virtual bool Execute(const void* weights, 
                         const float* activation,
                         float* output,
                         uint64_t N,
                         uint64_t K) = 0;
    
    // Get kernel metadata
    virtual const KernelDescriptor& GetDescriptor() const = 0;
};

/*===========================================================================
 * Concrete Kernel Implementations
 *===========================================================================*/

// Hot path: 4K dimension (most common) - Scalar
class QuantizedMatMul_4K : public IQuantizedMatMulKernel {
public:
    bool Execute(const void* weights, 
                 const float* activation,
                 float* output,
                 uint64_t N,
                 uint64_t K) override {
        (void)N; (void)K; // Statically known
        int result = QuantizedMatMul_Fused_4K(
            const_cast<void*>(weights),
            const_cast<float*>(activation),
            output,
            4096, 4096
        );
        return result == 1;
    }
    
    const KernelDescriptor& GetDescriptor() const override {
        static KernelDescriptor desc = {
            4096, 4096, "QuantizedMatMul_4K",
            reinterpret_cast<void*>(&QuantizedMatMul_Fused_4K),
            true
        };
        return desc;
    }
};

// Hot path: 4K dimension - AVX-512 optimized
class QuantizedMatMul_4K_AVX512 : public IQuantizedMatMulKernel {
public:
    bool Execute(const void* weights, 
                 const float* activation,
                 float* output,
                 uint64_t N,
                 uint64_t K) override {
        (void)N; (void)K; // Statically known
        int result = QuantizedMatMul_Fused_4K_AVX512(
            const_cast<void*>(weights),
            const_cast<float*>(activation),
            output,
            4096, 4096
        );
        return result == 1;
    }
    
    const KernelDescriptor& GetDescriptor() const override {
        static KernelDescriptor desc = {
            4096, 4096, "QuantizedMatMul_4K_AVX512",
            reinterpret_cast<void*>(&QuantizedMatMul_Fused_4K_AVX512),
            true
        };
        return desc;
    }
};

// Hot path: 4K dimension - 4-Way Accumulator AVX-512 (VAL-Q4.2)
class QuantizedMatMul_4K_4Way : public IQuantizedMatMulKernel {
public:
    bool Execute(const void* weights, 
                 const float* activation,
                 float* output,
                 uint64_t N,
                 uint64_t K) override {
        (void)N; (void)K; // Statically known
        int result = QuantizedMatMul_4Way_4K(
            const_cast<void*>(weights),
            const_cast<float*>(activation),
            output,
            4096, 4096
        );
        return result == 1;
    }
    
    const KernelDescriptor& GetDescriptor() const override {
        static KernelDescriptor desc = {
            4096, 4096, "QuantizedMatMul_4K_4Way",
            reinterpret_cast<void*>(&QuantizedMatMul_4Way_4K),
            true
        };
        return desc;
    }
};

// Hot path: 5K dimension (70B models)
class QuantizedMatMul_5K : public IQuantizedMatMulKernel {
public:
    bool Execute(const void* weights, 
                 const float* activation,
                 float* output,
                 uint64_t N,
                 uint64_t K) override {
        (void)N; (void)K;
        int result = QuantizedMatMul_Fused_5K(
            const_cast<void*>(weights),
            const_cast<float*>(activation),
            output,
            5120, 5120
        );
        return result == 1;
    }
    
    const KernelDescriptor& GetDescriptor() const override {
        static KernelDescriptor desc = {
            5120, 5120, "QuantizedMatMul_5K",
            reinterpret_cast<void*>(&QuantizedMatMul_Fused_5K),
            true
        };
        return desc;
    }
};

// Cold path: Dynamic dimensions
class QuantizedMatMul_Generic : public IQuantizedMatMulKernel {
public:
    bool Execute(const void* weights, 
                 const float* activation,
                 float* output,
                 uint64_t N,
                 uint64_t K) override {
        int result = QuantizedMatMul_Dynamic(
            const_cast<void*>(weights),
            const_cast<float*>(activation),
            output,
            N, K
        );
        return result == 1;
    }
    
    const KernelDescriptor& GetDescriptor() const override {
        static KernelDescriptor desc = {
            0, 0, "QuantizedMatMul_Dynamic",
            reinterpret_cast<void*>(&QuantizedMatMul_Dynamic),
            false
        };
        return desc;
    }
};

/*===========================================================================
 * Kernel Registry
 * Singleton for kernel dispatch and caching
 *===========================================================================*/
class KernelRegistry {
public:
    static KernelRegistry& Instance() {
        static KernelRegistry instance;
        return instance;
    }
    
    // Initialize registry - call once at startup
    bool Initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (initialized_) return true;
        
        // Check AVX-512 support
        if (!CheckAVX512Support()) {
            return false;
        }
        
        // Register hot path kernels
        RegisterKernel(4096, 4096, std::make_shared<QuantizedMatMul_4K>());
        RegisterKernel(4096, 4096, std::make_shared<QuantizedMatMul_4K_4Way>());  // VAL-Q4.2
        RegisterKernel(5120, 5120, std::make_shared<QuantizedMatMul_5K>());

        // Register fallback
        genericKernel_ = std::make_shared<QuantizedMatMul_Generic>();
        
        initialized_ = true;
        return true;
    }
    
    // Resolve kernel for given dimensions
    // Uses computed jump table for O(1) dispatch
    IQuantizedMatMulKernel* Resolve(uint64_t N, uint64_t K) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Check cache first
        auto key = (N << 32) | K;
        auto it = kernelCache_.find(key);
        if (it != kernelCache_.end()) {
            return it->second.get();
        }
        
        // Look for exact match
        for (const auto& [dimKey, kernel] : hotPathKernels_) {
            if (kernel->GetDescriptor().Matches(N, K)) {
                kernelCache_[key] = kernel;
                return kernel.get();
            }
        }
        
        // Fallback to generic
        return genericKernel_.get();
    }
    
    // Fast dispatch without cache lookup (for known dimensions)
    // Returns function pointer for direct call
    using KernelFunc = int (*)(void*, void*, void*, uint64_t, uint64_t);
    
    KernelFunc ResolveFast(uint64_t N, uint64_t K) {
        // Hot path: 4K and 5K
        if (N == 4096 && K == 4096) {
            return &QuantizedMatMul_Fused_4K;
        }
        if (N == 5120 && K == 5120) {
            return &QuantizedMatMul_Fused_5K;
        }
        
        // Cold path
        return &QuantizedMatMul_Dynamic;
    }
    
    // Get kernel statistics
    struct Stats {
        size_t hotPathHits;
        size_t coldPathHits;
        size_t cacheHits;
    };
    
    Stats GetStats() const {
        return {hotPathHits_, coldPathHits_, cacheHits_};
    }
    
private:
    KernelRegistry() = default;
    
    bool CheckAVX512Support() {
        // Call MASM initialization
        return RawrXD_KernelRegistry_Init() == 1;
    }
    
    void RegisterKernel(uint64_t N, uint64_t K, std::shared_ptr<IQuantizedMatMulKernel> kernel) {
        auto key = (N << 32) | K;
        hotPathKernels_[key] = std::move(kernel);
    }
    
    mutable std::mutex mutex_;
    bool initialized_ = false;
    
    std::unordered_map<uint64_t, std::shared_ptr<IQuantizedMatMulKernel>> hotPathKernels_;
    std::unordered_map<uint64_t, std::shared_ptr<IQuantizedMatMulKernel>> kernelCache_;
    std::shared_ptr<IQuantizedMatMulKernel> genericKernel_;
    
    // Stats
    mutable size_t hotPathHits_ = 0;
    mutable size_t coldPathHits_ = 0;
    mutable size_t cacheHits_ = 0;
};

/*===========================================================================
 * Telemetry Helper
 *===========================================================================*/
class KernelTelemetry {
public:
    struct Measurement {
        uint64_t startCycles;
        uint64_t endCycles;
        uint64_t durationCycles;
        const char* kernelName;
    };
    
    static void Begin() {
        currentStart_ = RawrXD_KernelTelemetry_Begin();
    }
    
    static void End(const char* kernelName) {
        uint64_t end = RawrXD_KernelTelemetry_End();
        // Store or log measurement
        (void)kernelName;
        (void)end;
    }
    
private:
    static thread_local uint64_t currentStart_;
};

thread_local uint64_t KernelTelemetry::currentStart_ = 0;

} // namespace Kernels
} // namespace RawrXD

/*===========================================================================
 * C API for External Integration
 *===========================================================================*/

extern "C" {

// Initialize kernel registry
__declspec(dllexport)
int RawrXD_Kernels_Initialize(void) {
    return RawrXD::Kernels::KernelRegistry::Instance().Initialize() ? 1 : 0;
}

// Execute quantized matmul with automatic dispatch
__declspec(dllexport)
int RawrXD_Kernels_QuantizedMatMul(
    const void* weights,
    const float* activation,
    float* output,
    uint64_t N,
    uint64_t K
) {
    auto* kernel = RawrXD::Kernels::KernelRegistry::Instance().Resolve(N, K);
    if (!kernel) return 0;
    
    return kernel->Execute(weights, activation, output, N, K) ? 1 : 0;
}

// Fast dispatch for known dimensions
__declspec(dllexport)
int RawrXD_Kernels_QuantizedMatMul_Fast(
    void* weights,
    void* activation,
    void* output,
    uint64_t N,
    uint64_t K
) {
    auto func = RawrXD::Kernels::KernelRegistry::Instance().ResolveFast(N, K);
    return func(weights, activation, output, N, K);
}

} // extern "C"
