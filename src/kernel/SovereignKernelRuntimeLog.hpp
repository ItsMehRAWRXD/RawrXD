/*===========================================================================
 * SovereignKernelRuntimeLog.hpp
 * 
 * Runtime logging and verification for kernel registry
 * 
 * Provides startup diagnostics showing:
 *   - Registered kernels
 *   - CPU feature detection
 *   - Selected kernel variants
 * 
 * Expected output format:
 *   [SovereignKernelRegistry]
 *   Registered:
 *     q4_k_m_dequant
 *     q4_k_m_matmul
 *   CPU Features:
 *     AVX2: YES
 *     AVX512: YES
 *   Selected:
 *     q4_k_m_dequant_avx512
 *===========================================================================*/

#pragma once

#include "SovereignKernelRegistry.hpp"
#include <cstdio>
#include <cstdarg>

namespace RawrXD {
namespace Kernel {

/*===========================================================================
 * Runtime Logger
 *===========================================================================*/
class KernelRuntimeLog {
public:
    enum class Level {
        Silent = 0,
        Error = 1,
        Warning = 2,
        Info = 3,
        Verbose = 4,
        Debug = 5
    };
    
    static KernelRuntimeLog& Instance() {
        static KernelRuntimeLog instance;
        return instance;
    }
    
    // Initialize with log level
    void Initialize(Level level = Level::Info) {
        level_ = level;
        initialized_ = true;
        
        if (level_ >= Level::Info) {
            PrintHeader();
        }
    }
    
    // Log formatted message
    void Log(Level level, const char* format, ...) {
        if (!initialized_ || level > level_) return;
        
        const char* prefix = GetLevelPrefix(level);
        
        va_list args;
        va_start(args, format);
        printf("%s", prefix);
        vprintf(format, args);
        printf("\n");
        va_end(args);
    }
    
    // Print kernel registry status
    void PrintRegistryStatus() {
        if (!initialized_ || level_ < Level::Info) return;
        
        printf("\n[SovereignKernelRegistry]\n");
        printf("Registered:\n");
        
        // List Q4_K_M kernels
        Q4KMRegistry().ListKernels([](const char* name, const KernelInfo* info) {
            printf("  %s (v%s, %s)\n", 
                   name, 
                   info->version,
                   info->isOptimized ? "optimized" : "generic");
        });
        
        // CPU Features
        printf("CPU Features:\n");
        auto& detector = CPUFeatureDetector::Instance();
        printf("  AVX2: %s\n", detector.HasAVX2() ? "YES" : "NO");
        printf("  AVX512: %s\n", detector.HasAVX512() ? "YES" : "NO");
        
        // Selected kernels
        printf("Selected:\n");
        auto q4km_kernel = GetQ4KMDequantKernel();
        if (q4km_kernel) {
            auto info = Q4KMRegistry().GetInfo("q4_k_m_dequant");
            if (info) {
                printf("  q4_k_m_dequant -> ");
                
                // Determine which variant was selected
                if (detector.HasAVX512()) {
                    printf("q4_k_m_dequant_avx512\n");
                } else if (detector.HasAVX2()) {
                    printf("q4_k_m_dequant_avx2\n");
                } else {
                    printf("q4_k_m_dequant (scalar)\n");
                }
            }
        }
        
        printf("\n");
    }
    
    // Print startup banner
    void PrintStartupBanner() {
        if (!initialized_ || level_ < Level::Info) return;
        
        printf("=================================================================\n");
        printf("  RawrXD Sovereign Runtime\n");
        printf("  Kernel Registry v1.0\n");
        printf("=================================================================\n");
        
        PrintRegistryStatus();
    }
    
    // Verification helpers
    bool VerifyKernelRegistration(const char* kernel_name) {
        auto kernel = Q4KMRegistry().Get(kernel_name);
        bool registered = (kernel != nullptr);
        
        Log(Level::Info, "Kernel '%s': %s", 
            kernel_name, 
            registered ? "REGISTERED" : "NOT FOUND");
        
        return registered;
    }
    
    bool VerifyCPUFeature(CPUFeature feature, const char* name) {
        auto& detector = CPUFeatureDetector::Instance();
        bool has_feature = false;
        
        switch (feature) {
            case CPUFeature::AVX2:
                has_feature = detector.HasAVX2();
                break;
            case CPUFeature::AVX512F:
                has_feature = detector.HasAVX512();
                break;
            default:
                break;
        }
        
        Log(Level::Info, "CPU Feature '%s': %s", 
            name, 
            has_feature ? "YES" : "NO");
        
        return has_feature;
    }

private:
    KernelRuntimeLog() = default;
    
    void PrintHeader() {
        // No-op - header printed in PrintStartupBanner
    }
    
    const char* GetLevelPrefix(Level level) {
        switch (level) {
            case Level::Error:   return "[ERROR] ";
            case Level::Warning: return "[WARN]  ";
            case Level::Info:    return "[INFO]  ";
            case Level::Verbose: return "[VERB]  ";
            case Level::Debug:   return "[DEBUG] ";
            default:             return "";
        }
    }
    
    Level level_ = Level::Info;
    bool initialized_ = false;
};

/*===========================================================================
 * Convenience Macros
 *===========================================================================*/

#define SOVEREIGN_LOG_ERROR(...)  \
    RawrXD::Kernel::KernelRuntimeLog::Instance().Log( \
        RawrXD::Kernel::KernelRuntimeLog::Level::Error, __VA_ARGS__)

#define SOVEREIGN_LOG_WARNING(...) \
    RawrXD::Kernel::KernelRuntimeLog::Instance().Log( \
        RawrXD::Kernel::KernelRuntimeLog::Level::Warning, __VA_ARGS__)

#define SOVEREIGN_LOG_INFO(...) \
    RawrXD::Kernel::KernelRuntimeLog::Instance().Log( \
        RawrXD::Kernel::KernelRuntimeLog::Level::Info, __VA_ARGS__)

#define SOVEREIGN_LOG_VERBOSE(...) \
    RawrXD::Kernel::KernelRuntimeLog::Instance().Log( \
        RawrXD::Kernel::KernelRuntimeLog::Level::Verbose, __VA_ARGS__)

#define SOVEREIGN_LOG_DEBUG(...) \
    RawrXD::Kernel::KernelRuntimeLog::Instance().Log( \
        RawrXD::Kernel::KernelRuntimeLog::Level::Debug, __VA_ARGS__)

} // namespace Kernel
} // namespace RawrXD

/*===========================================================================
 * C API for Runtime Verification
 *===========================================================================*/

extern "C" {

// Initialize runtime logging
__declspec(dllexport)
void SovereignKernelRuntime_InitLogging(int verbose) {
    using namespace RawrXD::Kernel;
    auto level = verbose ? KernelRuntimeLog::Level::Verbose : KernelRuntimeLog::Level::Info;
    KernelRuntimeLog::Instance().Initialize(level);
    KernelRuntimeLog::Instance().PrintStartupBanner();
}

// Print registry status
__declspec(dllexport)
void SovereignKernelRuntime_PrintStatus(void) {
    RawrXD::Kernel::KernelRuntimeLog::Instance().PrintRegistryStatus();
}

// Verify kernel registration
__declspec(dllexport)
int SovereignKernelRuntime_VerifyKernel(const char* kernel_name) {
    return RawrXD::Kernel::KernelRuntimeLog::Instance().VerifyKernelRegistration(kernel_name) ? 1 : 0;
}

// Get runtime log as string (for IDE display)
__declspec(dllexport)
const char* SovereignKernelRuntime_GetStatusString(void) {
    static thread_local char buffer[4096];
    
    // Build status string
    auto& detector = RawrXD::Kernel::CPUFeatureDetector::Instance();
    
    snprintf(buffer, sizeof(buffer),
        "[SovereignKernelRegistry]\n"
        "CPU Features:\n"
        "  AVX2: %s\n"
        "  AVX512: %s\n"
        "Q4_K_M: %s\n",
        detector.HasAVX2() ? "YES" : "NO",
        detector.HasAVX512() ? "YES" : "NO",
        RawrXD::Kernel::GetQ4KMDequantKernel() ? "AVAILABLE" : "NOT FOUND"
    );
    
    return buffer;
}

} // extern "C"
