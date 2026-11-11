/*===========================================================================
 * SovereignKernelRegistry.hpp
 * 
 * Central registry for all Sovereign MASM kernels
 * 
 * Provides dynamic dispatch based on CPU features:
 *   - Runtime kernel selection (AVX-512, AVX2, Scalar)
 *   - Version tracking and compatibility
 *   - Performance profiling hooks
 * 
 * Integration with Q4_K_M:
 *   KernelRegistry::Register("q4_k_m_dequant", Sovereign_Q4KM_DequantRange);
 *   auto kernel = KernelRegistry::Get<Q4KMDequantFunc>("q4_k_m_dequant");
 *===========================================================================*/

#pragma once

#include <cstdint>
#include <cstddef>
#include <functional>
#include <unordered_map>
#include <string>
#include <type_traits>

namespace RawrXD {
namespace Kernel {

/*===========================================================================
 * CPU Feature Detection
 *===========================================================================*/
enum class CPUFeature : uint32_t {
    None    = 0,
    SSE2    = 1 << 0,
    AVX     = 1 << 1,
    AVX2    = 1 << 2,
    AVX512F = 1 << 3,
    AVX512VL = 1 << 4,
    AVX512DQ = 1 << 5,
    AMX     = 1 << 6,
    All     = 0xFFFFFFFF
};

inline CPUFeature operator|(CPUFeature a, CPUFeature b) {
    return static_cast<CPUFeature>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b)
    );
}

inline CPUFeature operator&(CPUFeature a, CPUFeature b) {
    return static_cast<CPUFeature>(
        static_cast<uint32_t>(a) & static_cast<uint32_t>(b)
    );
}

inline bool HasFeature(CPUFeature features, CPUFeature check) {
    return (static_cast<uint32_t>(features) & static_cast<uint32_t>(check)) != 0;
}

/*===========================================================================
 * Kernel Metadata
 *===========================================================================*/
struct KernelInfo {
    const char* name;
    const char* version;
    CPUFeature requiredFeatures;
    CPUFeature preferredFeatures;
    uint64_t avgCyclesPerCall;
    uint64_t totalCalls;
    bool isOptimized;
};

/*===========================================================================
 * Kernel Registry
 * Template-based type-safe registry for kernel functions
 *===========================================================================*/
template<typename FuncType>
class KernelRegistry {
public:
    using KernelFunc = FuncType;
    using KernelMap = std::unordered_map<std::string, std::pair<KernelFunc, KernelInfo>>;
    
    static KernelRegistry& Instance() {
        static KernelRegistry instance;
        return instance;
    }
    
    // Register a kernel
    void Register(const char* name, KernelFunc func, const KernelInfo& info) {
        kernels_[name] = {func, info};
    }
    
    // Get kernel by name (returns nullptr if not found)
    KernelFunc Get(const char* name) const {
        auto it = kernels_.find(name);
        return (it != kernels_.end()) ? it->second.first : nullptr;
    }
    
    // Get kernel info
    const KernelInfo* GetInfo(const char* name) const {
        auto it = kernels_.find(name);
        return (it != kernels_.end()) ? &it->second.second : nullptr;
    }
    
    // Get best kernel based on CPU features
    KernelFunc GetBest(const char* baseName, CPUFeature available) const {
        // Try optimized versions first
        std::string avx512Name = std::string(baseName) + "_avx512";
        std::string avx2Name = std::string(baseName) + "_avx2";
        std::string sse2Name = std::string(baseName) + "_sse2";
        
        if (HasFeature(available, CPUFeature::AVX512F)) {
            auto func = Get(avx512Name.c_str());
            if (func) return func;
        }
        
        if (HasFeature(available, CPUFeature::AVX2)) {
            auto func = Get(avx2Name.c_str());
            if (func) return func;
        }
        
        // Fall back to base name (scalar)
        return Get(baseName);
    }
    
    // Update kernel stats
    void UpdateStats(const char* name, uint64_t cycles) {
        auto it = kernels_.find(name);
        if (it != kernels_.end()) {
            auto& info = it->second.second;
            info.avgCyclesPerCall = 
                (info.avgCyclesPerCall * info.totalCalls + cycles) / (info.totalCalls + 1);
            info.totalCalls++;
        }
    }
    
    // List all registered kernels
    void ListKernels(void (*callback)(const char* name, const KernelInfo* info)) const {
        for (const auto& [name, pair] : kernels_) {
            callback(name.c_str(), &pair.second);
        }
    }

private:
    KernelMap kernels_;
};

/*===========================================================================
 * Pre-defined Kernel Types
 *===========================================================================*/

// Q4_K_M Dequantization: (blocks, dest, num_blocks) -> values_processed
using Q4KMDequantFunc = uint64_t (*)(const uint8_t* blocks, float* dest, uint64_t num_blocks);

// Vector Dot Product: (a, b, out, n) -> void
using VecDotFunc = void (*)(const float* a, const float* b, float* out, size_t n);

// RMS Normalization: (x, out, n, eps) -> void
using RMSNormFunc = void (*)(const float* x, float* out, size_t n, float eps);

// SwiGLU Activation: (x, y, out, n) -> void
using SwiGLUFunc = void (*)(const float* x, const float* y, float* out, size_t n);

// Matrix-Vector Multiplication: (weights, x, y, rows, cols) -> void
using MatVecFunc = void (*)(const float* weights, const float* x, float* y, size_t rows, size_t cols);

/*===========================================================================
 * Typed Registry Accessors
 *===========================================================================*/

inline KernelRegistry<Q4KMDequantFunc>& Q4KMRegistry() {
    return KernelRegistry<Q4KMDequantFunc>::Instance();
}

inline KernelRegistry<VecDotFunc>& VecDotRegistry() {
    return KernelRegistry<VecDotFunc>::Instance();
}

inline KernelRegistry<RMSNormFunc>& RMSNormRegistry() {
    return KernelRegistry<RMSNormFunc>::Instance();
}

inline KernelRegistry<SwiGLUFunc>& SwiGLURegistry() {
    return KernelRegistry<SwiGLUFunc>::Instance();
}

inline KernelRegistry<MatVecFunc>& MatVecRegistry() {
    return KernelRegistry<MatVecFunc>::Instance();
}

/*===========================================================================
 * Registration Macros
 *===========================================================================*/

#define SOVEREIGN_REGISTER_KERNEL(type, name, func, features) \
    struct SovereignKernelReg_##name { \
        SovereignKernelReg_##name() { \
            RawrXD::Kernel::KernelRegistry<type>::Instance().Register( \
                #name, func, { #name, "1.0", features, features, 0, 0, true } \
            ); \
        } \
    } g_SovereignKernelReg_##name;

#define SOVEREIGN_REGISTER_Q4KM(name, func, features) \
    SOVEREIGN_REGISTER_KERNEL(RawrXD::Kernel::Q4KMDequantFunc, name, func, features)

#define SOVEREIGN_REGISTER_VECDOT(name, func, features) \
    SOVEREIGN_REGISTER_KERNEL(RawrXD::Kernel::VecDotFunc, name, func, features)

#define SOVEREIGN_REGISTER_RMSNORM(name, func, features) \
    SOVEREIGN_REGISTER_KERNEL(RawrXD::Kernel::RMSNormFunc, name, func, features)

#define SOVEREIGN_REGISTER_SWIGLU(name, func, features) \
    SOVEREIGN_REGISTER_KERNEL(RawrXD::Kernel::SwiGLUFunc, name, func, features)

/*===========================================================================
 * CPU Feature Detection Implementation
 *===========================================================================*/

class CPUFeatureDetector {
public:
    static CPUFeatureDetector& Instance() {
        static CPUFeatureDetector instance;
        return instance;
    }
    
    CPUFeature GetFeatures() const { return features_; }
    
    bool HasAVX512() const { return HasFeature(features_, CPUFeature::AVX512F); }
    bool HasAVX2() const { return HasFeature(features_, CPUFeature::AVX2); }
    bool HasAVX() const { return HasFeature(features_, CPUFeature::AVX); }
    bool HasSSE2() const { return HasFeature(features_, CPUFeature::SSE2); }

private:
    CPUFeatureDetector() { Detect(); }
    
    void Detect() {
        features_ = CPUFeature::None;
        
        #ifdef _WIN32
        int cpuInfo[4] = {0};
        
        // Check max function ID
        __cpuid(cpuInfo, 0);
        int maxFunc = cpuInfo[0];
        
        if (maxFunc >= 1) {
            __cpuid(cpuInfo, 1);
            
            // Check SSE2 (bit 26 of EDX)
            if (cpuInfo[3] & (1 << 26)) {
                features_ = features_ | CPUFeature::SSE2;
            }
            
            // Check AVX (bit 28 of ECX)
            if (cpuInfo[2] & (1 << 28)) {
                features_ = features_ | CPUFeature::AVX;
            }
        }
        
        if (maxFunc >= 7) {
            __cpuidex(cpuInfo, 7, 0);
            
            // Check AVX2 (bit 5 of EBX)
            if (cpuInfo[1] & (1 << 5)) {
                features_ = features_ | CPUFeature::AVX2;
            }
            
            // Check AVX-512F (bit 16 of EBX)
            if (cpuInfo[1] & (1 << 16)) {
                features_ = features_ | CPUFeature::AVX512F;
            }
            
            // Check AVX-512VL (bit 31 of EBX)
            if (cpuInfo[1] & (1 << 31)) {
                features_ = features_ | CPUFeature::AVX512VL;
            }
            
            // Check AVX-512DQ (bit 17 of EBX)
            if (cpuInfo[1] & (1 << 17)) {
                features_ = features_ | CPUFeature::AVX512DQ;
            }
        }
        #endif
    }
    
    CPUFeature features_ = CPUFeature::None;
};

/*===========================================================================
 * Kernel Dispatch Helper
 * Automatically selects best kernel based on CPU features
 *===========================================================================*/

template<typename FuncType>
FuncType GetBestKernel(const char* baseName) {
    auto& registry = KernelRegistry<FuncType>::Instance();
    auto features = CPUFeatureDetector::Instance().GetFeatures();
    return registry.GetBest(baseName, features);
}

// Convenience function for Q4_K_M
inline Q4KMDequantFunc GetQ4KMDequantKernel() {
    return GetBestKernel<Q4KMDequantFunc>("q4_k_m_dequant");
}

} // namespace Kernel
} // namespace RawrXD

/*===========================================================================
 * C API for MASM Integration
 *===========================================================================*/

extern "C" {

// Get CPU feature flags
__declspec(dllexport)
uint32_t SovereignKernel_GetCPUFeatures(void) {
    return static_cast<uint32_t>(
        RawrXD::Kernel::CPUFeatureDetector::Instance().GetFeatures()
    );
}

// Check if specific feature is available
__declspec(dllexport)
int SovereignKernel_HasAVX512(void) {
    return RawrXD::Kernel::CPUFeatureDetector::Instance().HasAVX512() ? 1 : 0;
}

__declspec(dllexport)
int SovereignKernel_HasAVX2(void) {
    return RawrXD::Kernel::CPUFeatureDetector::Instance().HasAVX2() ? 1 : 0;
}

// Get kernel version string
__declspec(dllexport)
const char* SovereignKernel_GetVersion(const char* kernelName) {
    auto info = RawrXD::Kernel::Q4KMRegistry().GetInfo(kernelName);
    return info ? info->version : "unknown";
}

} // extern "C"
