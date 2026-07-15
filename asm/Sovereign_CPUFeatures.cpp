//============================================================================
// Sovereign_CPUFeatures.cpp
// CPU Feature Detection Implementation
//
// Uses CPUID to detect processor capabilities
// Phase 7C: Runtime Dispatch Foundation
//============================================================================

#include "Sovereign_CPUFeatures.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>

// Platform-specific includes
#ifdef _WIN32
#include <intrin.h>
#else
#include <cpuid.h>
#endif

namespace Sovereign {

//============================================================================
// CPUID WRAPPER
//============================================================================

static void cpuid(int info[4], int function)
{
#ifdef _WIN32
    __cpuid(info, function);
#else
    __cpuid_count(function, 0, info[0], info[1], info[2], info[3]);
#endif
}

static void cpuidex(int info[4], int function, int subfunction)
{
#ifdef _WIN32
    __cpuidex(info, function, subfunction);
#else
    __cpuid_count(function, subfunction, info[0], info[1], info[2], info[3]);
#endif
}

static uint64_t xgetbv(uint32_t xcr)
{
#ifdef _WIN32
    return _xgetbv(xcr);
#else
    uint32_t eax, edx;
    __asm__ __volatile__("xgetbv" : "=a"(eax), "=d"(edx) : "c"(xcr));
    return (static_cast<uint64_t>(edx) << 32) | eax;
#endif
}

//============================================================================
// BACKEND STRING CONVERSIONS
//============================================================================

const char* KernelBackendToString(KernelBackend backend)
{
    switch (backend)
    {
        case KernelBackend::Scalar:     return "Scalar";
        case KernelBackend::SSE42:      return "SSE4.2";
        case KernelBackend::AVX2:       return "AVX2";
        case KernelBackend::AVX512:     return "AVX-512";
        case KernelBackend::AMX:       return "AMX";
        case KernelBackend::TitanGPU:   return "TitanGPU";
        case KernelBackend::VulkanGPU:  return "VulkanGPU";
        default:                        return "Unknown";
    }
}

KernelBackend StringToKernelBackend(const char* str)
{
    if (strcmp(str, "Scalar") == 0)     return KernelBackend::Scalar;
    if (strcmp(str, "SSE4.2") == 0)    return KernelBackend::SSE42;
    if (strcmp(str, "AVX2") == 0)      return KernelBackend::AVX2;
    if (strcmp(str, "AVX-512") == 0)   return KernelBackend::AVX512;
    if (strcmp(str, "AMX") == 0)       return KernelBackend::AMX;
    if (strcmp(str, "TitanGPU") == 0)  return KernelBackend::TitanGPU;
    if (strcmp(str, "VulkanGPU") == 0) return KernelBackend::VulkanGPU;
    return KernelBackend::Scalar;
}

//============================================================================
// CPU INFO METHODS
//============================================================================

KernelBackend CPUInfo::GetBestBackend() const
{
    if (Has(CPUFeature::AVX512F) && Has(CPUFeature::AVX512VL))
        return KernelBackend::AVX512;
    if (Has(CPUFeature::AVX2))
        return KernelBackend::AVX2;
    if (Has(CPUFeature::SSE42))
        return KernelBackend::SSE42;
    return KernelBackend::Scalar;
}

std::string CPUInfo::ToString() const
{
    std::ostringstream oss;
    oss << "CPU: " << brand << "\n"
        << "  Vendor: " << vendor << "\n"
        << "  Family: " << family << ", Model: " << model << ", Stepping: " << stepping << "\n"
        << "  Cores: " << physicalCores << " physical, " << logicalCores << " logical\n"
        << "  Cache: L1=" << (L1CacheSize / 1024) << "KB, L2=" << (L2CacheSize / 1024) << "KB, L3=" << (L3CacheSize / (1024*1024)) << "MB\n"
        << "  Features:";
    
    if (Has(CPUFeature::AVX512F)) oss << " AVX-512";
    if (Has(CPUFeature::AVX2)) oss << " AVX2";
    if (Has(CPUFeature::AVX)) oss << " AVX";
    if (Has(CPUFeature::SSE42)) oss << " SSE4.2";
    if (Has(CPUFeature::FMA3)) oss << " FMA3";
    if (Has(CPUFeature::AMX_TILE)) oss << " AMX";
    
    oss << "\n  Best Backend: " << KernelBackendToString(GetBestBackend());
    
    return oss.str();
}

//============================================================================
// CPU FEATURE DETECTOR - SINGLETON
//============================================================================

CPUFeatureDetector& CPUFeatureDetector::Instance()
{
    static CPUFeatureDetector instance;
    return instance;
}

bool CPUFeatureDetector::Initialize()
{
    if (initialized_)
        return true;
    
    DetectVendor();
    DetectFeatures();
    DetectCacheInfo();
    
    initialized_ = true;
    return true;
}

bool CPUFeatureDetector::Has(CPUFeature feature) const
{
    return cpuInfo_.Has(feature);
}

KernelBackend CPUFeatureDetector::GetBestBackend() const
{
    return cpuInfo_.GetBestBackend();
}

std::string CPUFeatureDetector::GetFeatureString() const
{
    return cpuInfo_.ToString();
}

void CPUFeatureDetector::PrintInfo() const
{
    std::cout << GetFeatureString() << std::endl;
}

//============================================================================
// DETECTION IMPLEMENTATION
//============================================================================

void CPUFeatureDetector::DetectVendor()
{
    int info[4] = {0};
    
    // Get vendor string
    cpuid(info, 0);
    int nIds = info[0];
    
    // Vendor string is in EBX, EDX, ECX (in that order)
    char vendor[13] = {0};
    memcpy(vendor, &info[1], 4);  // EBX
    memcpy(vendor + 4, &info[3], 4);  // EDX
    memcpy(vendor + 8, &info[2], 4);  // ECX
    
    strncpy(cpuInfo_.vendor, vendor, 12);
    
    // Get brand string (if supported)
    if (nIds >= 0x80000000)
    {
        cpuid(info, 0x80000000);
        unsigned nExIds = info[0];
        
        if (nExIds >= 0x80000004)
        {
            char brand[49] = {0};
            cpuid(info, 0x80000002);
            memcpy(brand, info, 16);
            cpuid(info, 0x80000003);
            memcpy(brand + 16, info, 16);
            cpuid(info, 0x80000004);
            memcpy(brand + 32, info, 16);
            
            strncpy(cpuInfo_.brand, brand, 48);
        }
    }
    
    // Get family/model/stepping
    cpuid(info, 1);
    cpuInfo_.stepping = info[0] & 0xF;
    cpuInfo_.model = ((info[0] >> 4) & 0xF) | ((info[0] >> 12) & 0xF0);
    cpuInfo_.family = ((info[0] >> 8) & 0xF) | ((info[0] >> 20) & 0xFF);
    
    // Get core count
    if (nIds >= 1)
    {
        cpuid(info, 1);
        cpuInfo_.logicalCores = (info[1] >> 16) & 0xFF;
    }
    
    if (nIds >= 4)
    {
        cpuidex(info, 4, 0);
        cpuInfo_.physicalCores = ((info[0] >> 26) & 0x3F) + 1;
    }
}

void CPUFeatureDetector::DetectFeatures()
{
    int info[4] = {0};
    uint64_t features = 0;
    
    // Basic features (CPUID 1)
    cpuid(info, 1);
    
    // ECX features
    if (info[2] & (1 << 0))  features |= static_cast<uint64_t>(CPUFeature::SSE3);
    if (info[2] & (1 << 1))  features |= static_cast<uint64_t>(CPUFeature::SSSE3);
    if (info[2] & (1 << 9))  features |= static_cast<uint64_t>(CPUFeature::SSSE3);
    if (info[2] & (1 << 19)) features |= static_cast<uint64_t>(CPUFeature::SSE41);
    if (info[2] & (1 << 20)) features |= static_cast<uint64_t>(CPUFeature::SSE42);
    if (info[2] & (1 << 23)) features |= static_cast<uint64_t>(CPUFeature::POPCNT);
    if (info[2] & (1 << 28)) features |= static_cast<uint64_t>(CPUFeature::AVX);
    if (info[2] & (1 << 12)) features |= static_cast<uint64_t>(CPUFeature::FMA3);
    
    // EDX features
    if (info[3] & (1 << 26)) features |= static_cast<uint64_t>(CPUFeature::SSE2);
    
    // Extended features (CPUID 7)
    cpuidex(info, 7, 0);
    
    // EBX features
    if (info[1] & (1 << 5))  features |= static_cast<uint64_t>(CPUFeature::AVX2);
    if (info[1] & (1 << 3))  features |= static_cast<uint64_t>(CPUFeature::BMI1);
    if (info[1] & (1 << 8))  features |= static_cast<uint64_t>(CPUFeature::BMI2);
    if (info[1] & (1 << 16)) features |= static_cast<uint64_t>(CPUFeature::AVX512F);
    if (info[1] & (1 << 17)) features |= static_cast<uint64_t>(CPUFeature::AVX512DQ);
    if (info[1] & (1 << 30)) features |= static_cast<uint64_t>(CPUFeature::AVX512BW);
    if (info[1] & (1 << 31)) features |= static_cast<uint64_t>(CPUFeature::AVX512VL);
    if (info[1] & (1 << 28)) features |= static_cast<uint64_t>(CPUFeature::AVX512CD);
    if (info[1] & (1 << 1))  features |= static_cast<uint64_t>(CPUFeature::AVX512VBMI);
    if (info[1] & (1 << 21)) features |= static_cast<uint64_t>(CPUFeature::AVX512IFMA);
    if (info[1] & (1 << 11)) features |= static_cast<uint64_t>(CPUFeature::AVX512VNNI);
    
    // ECX features
    if (info[2] & (1 << 24)) features |= static_cast<uint64_t>(CPUFeature::AMX_TILE);
    if (info[2] & (1 << 25)) features |= static_cast<uint64_t>(CPUFeature::AMX_INT8);
    if (info[2] & (1 << 22)) features |= static_cast<uint64_t>(CPUFeature::AMX_BF16);
    
    // Check XCR0 for AVX/AVX-512 OS support
    if (features & static_cast<uint64_t>(CPUFeature::AVX))
    {
        uint64_t xcr0 = xgetbv(0);
        bool osSupportsAVX = (xcr0 & 0x6) == 0x6;  // XMM and YMM state
        
        if (!osSupportsAVX)
        {
            // Disable AVX features if OS doesn't support
            features &= ~static_cast<uint64_t>(CPUFeature::AVX);
            features &= ~static_cast<uint64_t>(CPUFeature::AVX2);
            features &= ~static_cast<uint64_t>(CPUFeature::AVX512F);
        }
        else if (features & static_cast<uint64_t>(CPUFeature::AVX512F))
        {
            // Check for AVX-512 OS support (ZMM state)
            bool osSupportsAVX512 = (xcr0 & 0xE0) == 0xE0;  // ZMM state
            if (!osSupportsAVX512)
            {
                // Disable AVX-512 features
                features &= ~static_cast<uint64_t>(CPUFeature::AVX512F);
                features &= ~static_cast<uint64_t>(CPUFeature::AVX512DQ);
                features &= ~static_cast<uint64_t>(CPUFeature::AVX512BW);
                features &= ~static_cast<uint64_t>(CPUFeature::AVX512VL);
                features &= ~static_cast<uint64_t>(CPUFeature::AVX512CD);
                features &= ~static_cast<uint64_t>(CPUFeature::AVX512VBMI);
                features &= ~static_cast<uint64_t>(CPUFeature::AVX512IFMA);
                features &= ~static_cast<uint64_t>(CPUFeature::AVX512VNNI);
            }
        }
    }
    
    cpuInfo_.features = features;
}

void CPUFeatureDetector::DetectCacheInfo()
{
    int info[4] = {0};
    
    // Cache line size
    cpuid(info, 1);
    cpuInfo_.cacheLineSize = ((info[1] >> 8) & 0xFF) * 8;
    
    // Cache sizes (CPUID 4)
    cpuidex(info, 4, 0);
    if ((info[0] & 0x1F) != 0)  // Valid cache
    {
        int ways = ((info[0] >> 22) & 0x3FF) + 1;
        int partitions = ((info[0] >> 12) & 0x3FF) + 1;
        int lineSize = (info[0] & 0xFFF) + 1;
        int sets = info[1] + 1;
        cpuInfo_.L1CacheSize = ways * partitions * lineSize * sets;
    }
    
    // L2 cache
    cpuidex(info, 4, 2);
    if ((info[0] & 0x1F) != 0)
    {
        int ways = ((info[0] >> 22) & 0x3FF) + 1;
        int partitions = ((info[0] >> 12) & 0x3FF) + 1;
        int lineSize = (info[0] & 0xFFF) + 1;
        int sets = info[1] + 1;
        cpuInfo_.L2CacheSize = ways * partitions * lineSize * sets;
    }
    
    // L3 cache
    cpuidex(info, 4, 3);
    if ((info[0] & 0x1F) != 0)
    {
        int ways = ((info[0] >> 22) & 0x3FF) + 1;
        int partitions = ((info[0] >> 12) & 0x3FF) + 1;
        int lineSize = (info[0] & 0xFFF) + 1;
        int sets = info[1] + 1;
        cpuInfo_.L3CacheSize = ways * partitions * lineSize * sets;
    }
}

} // namespace Sovereign
