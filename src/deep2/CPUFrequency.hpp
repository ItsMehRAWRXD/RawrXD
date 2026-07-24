// ============================================================================
// CPUFrequency.hpp - Reliable CPU Frequency Detection with Antidote Integration
//
// Features:
//   - Multiple detection methods (CPUID 0x15, TSC calibration, OS APIs)
//   - Guaranteed non-zero return (never returns 0.0)
//   - Automatic antidote reapplication on invalid readings
//   - Caching for performance
//
// The Antidote ensures frequency detection integrity.
// ============================================================================

#ifndef DEEP2_CPU_FREQUENCY_HPP
#define DEEP2_CPU_FREQUENCY_HPP

#include <cstdint>
#include <atomic>
#include <mutex>

namespace Deep2 {

// ============================================================================
// CPU Frequency Detection
// ============================================================================

class CPUFrequency {
public:
    // Get CPU frequency in GHz
    // Guaranteed to return > 0.0 (never returns 0.0 or negative)
    static double GetCPUGHz();
    
    // Get raw frequency in Hz
    static uint64_t GetCPUFrequencyHz();
    
    // Check if frequency is valid (> 0)
    static bool IsValid(double freqGHz);
    
    // Force recalculation (clears cache)
    static void InvalidateCache();
    
    // Get detection method used
    enum class DetectionMethod {
        CPUID_15,       // CPUID leaf 0x15 (most accurate)
        TSC_CALIBRATION,// TSC calibration
        OS_API,         // Windows/Linux OS API
        ESTIMATED       // Fallback estimate
    };
    static DetectionMethod GetLastMethod();
    
    // Get last error (if any)
    static const char* GetLastError();

private:
    static std::atomic<double> cachedFreqGHz_;
    static std::atomic<bool> cacheValid_;
    static std::mutex mutex_;
    static DetectionMethod lastMethod_;
    static const char* lastError_;
    
    // Detection implementations
    static double TryCPUID15();
    static double TryTSCCalibration();
    static double TryOSAPI();
    static double GetEstimatedFrequency();
    
    // Platform-specific
#ifdef _WIN32
    static double TryWindowsAPI();
#else
    static double TryLinuxAPI();
#endif
};

// ============================================================================
// Convenience Function
// ============================================================================

inline double GetCPUGHz() {
    return CPUFrequency::GetCPUGHz();
}

} // namespace Deep2

#endif // DEEP2_CPU_FREQUENCY_HPP
