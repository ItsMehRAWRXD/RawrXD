//============================================================================
// Sovereign_CPUFeatures.hpp
// Centralized CPU Feature Detection for Kernel Dispatch
//
// Phase 7C: Runtime Dispatch Foundation
// Date: 2026-07-10
//============================================================================

#pragma once

#include <cstdint>
#include <string>

namespace Sovereign {

//============================================================================
// CPU FEATURE FLAGS
//============================================================================

enum class CPUFeature : uint64_t
{
    // Basic x86-64
    SSE2        = 1ULL << 0,
    SSE3        = 1ULL << 1,
    SSSE3       = 1ULL << 2,
    SSE41       = 1ULL << 3,
    SSE42       = 1ULL << 4,
    
    // AVX Family
    AVX         = 1ULL << 10,
    AVX2        = 1ULL << 11,
    AVX512F     = 1ULL << 12,    // Foundation
    AVX512DQ    = 1ULL << 13,    // Double/Quadword
    AVX512BW    = 1ULL << 14,    // Byte/Word
    AVX512VL    = 1ULL << 15,    // Vector Length
    AVX512CD    = 1ULL << 16,    // Conflict Detection
    AVX512VBMI  = 1ULL << 17,    // Vector Byte Manipulation
    AVX512IFMA  = 1ULL << 18,    // Integer FMA
    AVX512VNNI  = 1ULL << 19,    // Neural Network Instructions
    
    // AMX (Advanced Matrix Extensions)
    AMX_TILE    = 1ULL << 20,
    AMX_INT8    = 1ULL << 21,
    AMX_BF16    = 1ULL << 22,
    
    // Other
    FMA3        = 1ULL << 30,
    BMI1        = 1ULL << 31,
    BMI2        = 1ULL << 32,
    LZCNT       = 1ULL << 33,
    POPCNT      = 1ULL << 34,
    
    // GPU (for Titan integration)
    TITAN_GPU   = 1ULL << 40,
    VULKAN_COMPUTE = 1ULL << 41,
};

inline CPUFeature operator|(CPUFeature a, CPUFeature b)
{
    return static_cast<CPUFeature>(static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
}

inline CPUFeature operator&(CPUFeature a, CPUFeature b)
{
    return static_cast<CPUFeature>(static_cast<uint64_t>(a) & static_cast<uint64_t>(b));
}

inline bool HasFeature(CPUFeature flags, CPUFeature feature)
{
    return (static_cast<uint64_t>(flags) & static_cast<uint64_t>(feature)) != 0;
}

//============================================================================
// BACKEND ENUM
//============================================================================

enum class KernelBackend
{
    Scalar,         // Reference C++ implementation
    SSE42,          // SSE4.2 optimized
    AVX2,           // AVX2 optimized
    AVX512,         // AVX-512 optimized
    AMX,            // Advanced Matrix Extensions
    TitanGPU,       // Titan GPU runtime
    VulkanGPU,      // Vulkan compute shaders
    
    Count           // Number of backends
};

const char* KernelBackendToString(KernelBackend backend);
KernelBackend StringToKernelBackend(const char* str);

//============================================================================
// CPU INFO STRUCTURE
//============================================================================

struct CPUInfo
{
    char vendor[13];           // CPU vendor string (GenuineIntel, AuthenticAMD)
    char brand[49];            // CPU brand string
    uint32_t family;
    uint32_t model;
    uint32_t stepping;
    uint32_t logicalCores;
    uint32_t physicalCores;
    uint64_t features;         // Bitmask of CPUFeature
    uint32_t cacheLineSize;
    uint32_t L1CacheSize;
    uint32_t L2CacheSize;
    uint32_t L3CacheSize;
    
    // Feature check helpers
    bool Has(CPUFeature feature) const
    {
        return (features & static_cast<uint64_t>(feature)) != 0;
    }
    
    bool HasAVX512() const
    {
        return Has(CPUFeature::AVX512F);
    }
    
    bool HasAVX2() const
    {
        return Has(CPUFeature::AVX2);
    }
    
    bool HasAVX() const
    {
        return Has(CPUFeature::AVX);
    }
    
    bool HasSSE42() const
    {
        return Has(CPUFeature::SSE42);
    }
    
    KernelBackend GetBestBackend() const;
    std::string ToString() const;
};

//============================================================================
// CPU FEATURE DETECTOR
//============================================================================

class CPUFeatureDetector
{
public:
    // Singleton access
    static CPUFeatureDetector& Instance();
    
    // Initialize (call once at startup)
    bool Initialize();
    bool IsInitialized() const { return initialized_; }
    
    // Get detected CPU info
    const CPUInfo& GetCPUInfo() const { return cpuInfo_; }
    
    // Check specific features
    bool Has(CPUFeature feature) const;
    bool HasAVX512() const { return Has(CPUFeature::AVX512F); }
    bool HasAVX2() const { return Has(CPUFeature::AVX2); }
    bool HasAVX() const { return Has(CPUFeature::AVX); }
    bool HasSSE42() const { return Has(CPUFeature::SSE42); }
    bool HasFMA3() const { return Has(CPUFeature::FMA3); }
    bool HasAMX() const { return Has(CPUFeature::AMX_TILE); }
    
    // Get best backend for this CPU
    KernelBackend GetBestBackend() const;
    
    // Get feature string for logging
    std::string GetFeatureString() const;
    
    // Print CPU info to console
    void PrintInfo() const;

private:
    CPUFeatureDetector() = default;
    ~CPUFeatureDetector() = default;
    
    CPUFeatureDetector(const CPUFeatureDetector&) = delete;
    CPUFeatureDetector& operator=(const CPUFeatureDetector&) = delete;
    
    void DetectVendor();
    void DetectFeatures();
    void DetectCacheInfo();
    
    bool initialized_ = false;
    CPUInfo cpuInfo_ = {};
};

//============================================================================
// CONVENIENCE MACROS
//============================================================================

#define SOVEREIGN_CPU_FEATURES (::Sovereign::CPUFeatureDetector::Instance())

} // namespace Sovereign
