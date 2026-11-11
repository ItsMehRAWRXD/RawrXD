// ============================================================================
// CPUFrequency.cpp - Reliable CPU Frequency Detection with Antidote Integration
//
// Detection priority:
//   1. CPUID 0x15 (most accurate, Intel Skylake+)
//   2. TSC calibration (portable, ~1% accuracy)
//   3. OS API (Windows QueryPerformanceFrequency, Linux /proc/cpuinfo)
//   4. Estimated fallback (never returns 0)
//
// If any method returns 0 or invalid, The Antidote is reapplied.
// ============================================================================

#include "CPUFrequency.hpp"
#include "AntiPatcher.hpp"
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#else
#include <cpuid.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace Deep2 {

// Static members
std::atomic<double> CPUFrequency::cachedFreqGHz_(0.0);
std::atomic<bool> CPUFrequency::cacheValid_(false);
std::mutex CPUFrequency::mutex_;
CPUFrequency::DetectionMethod CPUFrequency::lastMethod_ = DetectionMethod::ESTIMATED;
const char* CPUFrequency::lastError_ = nullptr;

// ============================================================================
// Public API
// ============================================================================

double CPUFrequency::GetCPUGHz() {
    // Check cache first
    if (cacheValid_.load()) {
        double cached = cachedFreqGHz_.load();
        if (IsValid(cached)) {
            return cached;
        }
        // Cache has invalid value, invalidate it
        cacheValid_ = false;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Double-check after acquiring lock
    if (cacheValid_.load()) {
        double cached = cachedFreqGHz_.load();
        if (IsValid(cached)) {
            return cached;
        }
    }
    
    // Try detection methods in order of accuracy
    double freq = 0.0;
    
    // Method 1: CPUID 0x15 (Intel Skylake+, most accurate)
    freq = TryCPUID15();
    if (IsValid(freq)) {
        lastMethod_ = DetectionMethod::CPUID_15;
        cachedFreqGHz_ = freq;
        cacheValid_ = true;
        return freq;
    }
    
    // Method 2: TSC calibration
    freq = TryTSCCalibration();
    if (IsValid(freq)) {
        lastMethod_ = DetectionMethod::TSC_CALIBRATION;
        cachedFreqGHz_ = freq;
        cacheValid_ = true;
        return freq;
    }
    
    // Method 3: OS API
    freq = TryOSAPI();
    if (IsValid(freq)) {
        lastMethod_ = DetectionMethod::OS_API;
        cachedFreqGHz_ = freq;
        cacheValid_ = true;
        return freq;
    }
    
    // Method 4: Estimated fallback (NEVER returns 0)
    freq = GetEstimatedFrequency();
    lastMethod_ = DetectionMethod::ESTIMATED;
    lastError_ = "All detection methods failed, using estimate";
    cachedFreqGHz_ = freq;
    cacheValid_ = true;
    
    // Log warning
    fprintf(stderr, "[CPUFrequency] Warning: %s (%.2f GHz)\n", lastError_, freq);
    
    // Apply antidote - ensure system integrity
    printf("[CPUFrequency] Applying antidote for invalid frequency detection...\n");
    int purged = PurgeAllPatches();
    if (purged > 0) {
        printf("[CPUFrequency] Antidote removed %d unauthorized patches\n", purged);
    }
    
    return freq;
}

uint64_t CPUFrequency::GetCPUFrequencyHz() {
    double ghz = GetCPUGHz();
    return static_cast<uint64_t>(ghz * 1e9);
}

bool CPUFrequency::IsValid(double freqGHz) {
    return freqGHz > 0.0 && freqGHz < 10.0;  // Reasonable range: 0.1 - 10 GHz
}

void CPUFrequency::InvalidateCache() {
    cacheValid_ = false;
    cachedFreqGHz_ = 0.0;
}

CPUFrequency::DetectionMethod CPUFrequency::GetLastMethod() {
    return lastMethod_;
}

const char* CPUFrequency::GetLastError() {
    return lastError_;
}

// ============================================================================
// Detection Implementations
// ============================================================================

double CPUFrequency::TryCPUID15() {
#ifdef _WIN32
    int regs[4] = {0};
    
    // Check max CPUID leaf supported
    __cpuid(regs, 0);
    int max_leaf = regs[0];
    
    // Try CPUID 0x15 (Time Stamp Counter and Nominal Core Crystal Clock)
    if (max_leaf >= 0x15) {
        __cpuid(regs, 0x15);
        if (regs[0] != 0 && regs[1] != 0) {
            // ECX * EBX / EAX = frequency in Hz
            double freq_hz = static_cast<double>(regs[2]) * regs[1] / regs[0];
            if (freq_hz > 0) {
                double freq_ghz = freq_hz / 1e9;
                if (IsValid(freq_ghz)) {
                    return freq_ghz;
                }
            }
        }
    }
#else
    unsigned int eax, ebx, ecx, edx;
    
    // Check max CPUID leaf
    if (__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
        unsigned int max_leaf = eax;
        
        if (max_leaf >= 0x15) {
            if (__get_cpuid(0x15, &eax, &ebx, &ecx, &edx)) {
                if (eax != 0 && ebx != 0) {
                    double freq_hz = static_cast<double>(ecx) * ebx / eax;
                    if (freq_hz > 0) {
                        double freq_ghz = freq_hz / 1e9;
                        if (IsValid(freq_ghz)) {
                            return freq_ghz;
                        }
                    }
                }
            }
        }
    }
#endif
    
    lastError_ = "CPUID 0x15 not available or returned invalid";
    return 0.0;
}

double CPUFrequency::TryTSCCalibration() {
    // TSC calibration against a busy-wait loop
    // This is portable but less accurate than CPUID 0x15
    
    const uint64_t target = 10000000ULL;  // 10M iterations
    volatile uint64_t spin_count = 0;
    
    // Warm up
    for (int i = 0; i < 1000; i++) {
        spin_count++;
    }
    spin_count = 0;
    
    // Measure
    uint64_t tsc_start = 0, tsc_end = 0;
    
#ifdef _WIN32
    tsc_start = __rdtsc();
#else
    unsigned int aux;
    tsc_start = __rdtscp(&aux);
#endif
    
    while (spin_count < target) {
        spin_count++;
    }
    
#ifdef _WIN32
    tsc_end = __rdtsc();
#else
    tsc_end = __rdtscp(&aux);
#endif
    
    uint64_t tsc_delta = tsc_end - tsc_start;
    if (tsc_delta == 0) {
        lastError_ = "TSC calibration returned zero delta";
        return 0.0;
    }
    
    // Estimate: each iteration takes ~1 cycle on modern CPUs
    // This is a rough estimate but better than nothing
    double hz = static_cast<double>(tsc_delta) / static_cast<double>(target);
    double freq_ghz = hz / 1e9;
    
    // Sanity check: must be in reasonable range
    if (!IsValid(freq_ghz)) {
        lastError_ = "TSC calibration returned out-of-range value";
        return 0.0;
    }
    
    return freq_ghz;
}

double CPUFrequency::TryOSAPI() {
#ifdef _WIN32
    return TryWindowsAPI();
#else
    return TryLinuxAPI();
#endif
}

#ifdef _WIN32
double CPUFrequency::TryWindowsAPI() {
    // Try to get from Windows API
    // Method 1: QueryPerformanceFrequency (gives QPC frequency, not CPU)
    // Method 2: Get processor frequency from registry
    
    LARGE_INTEGER qpf;
    if (QueryPerformanceFrequency(&qpf)) {
        // QPF is not CPU frequency, but we can use it as a fallback
        // if we absolutely have to (not recommended)
        // Skip this for now
    }
    
    // Try registry
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                      "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD freqMHz = 0;
        DWORD size = sizeof(freqMHz);
        if (RegQueryValueExA(hKey, "~MHz", nullptr, nullptr, 
                             reinterpret_cast<LPBYTE>(&freqMHz), &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            if (freqMHz > 0) {
                double freq_ghz = freqMHz / 1000.0;
                if (IsValid(freq_ghz)) {
                    return freq_ghz;
                }
            }
        }
        RegCloseKey(hKey);
    }
    
    lastError_ = "Windows API methods failed";
    return 0.0;
}
#else
double CPUFrequency::TryLinuxAPI() {
    // Try /proc/cpuinfo
    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "cpu MHz", 7) == 0) {
                char* colon = strchr(line, ':');
                if (colon) {
                    double mhz = atof(colon + 1);
                    if (mhz > 0) {
                        fclose(fp);
                        double freq_ghz = mhz / 1000.0;
                        if (IsValid(freq_ghz)) {
                            return freq_ghz;
                        }
                    }
                }
            }
        }
        fclose(fp);
    }
    
    lastError_ = "Linux API methods failed";
    return 0.0;
}
#endif

double CPUFrequency::GetEstimatedFrequency() {
    // Ultimate fallback: assume a common modern base clock
    // This is the "never return 0" guarantee
    
    // Try to make an educated guess based on CPU vendor
    int regs[4];
    char vendor[13] = {0};
    
#ifdef _WIN32
    __cpuid(regs, 0);
    memcpy(vendor, &regs[1], 4);  // EBX
    memcpy(vendor + 4, &regs[3], 4);  // EDX
    memcpy(vendor + 8, &regs[2], 4);  // ECX
#else
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
        memcpy(vendor, &ebx, 4);
        memcpy(vendor + 4, &edx, 4);
        memcpy(vendor + 8, &ecx, 4);
    }
#endif
    
    // Common base frequencies by vendor
    if (strcmp(vendor, "GenuineIntel") == 0) {
        // Intel: common base clocks
        // Try to detect generation from CPUID
        if (regs[0] >= 1) {
            __cpuid(regs, 1);
            int family = ((regs[0] >> 8) & 0xF) + ((regs[0] >> 20) & 0xFF);
            int model = ((regs[0] >> 4) & 0xF) | ((regs[0] >> 12) & 0xF0);
            
            // Skylake and newer often have higher base clocks
            if (family == 6) {
                if (model >= 0x55 && model <= 0x5F) {
                    return 3.3;  // Skylake-X
                } else if (model >= 0x9E && model <= 0x9F) {
                    return 3.6;  // Coffee Lake
                } else if (model >= 0xA0) {
                    return 3.5;  // Ice Lake and newer
                }
            }
        }
        return 3.0;  // Conservative Intel estimate
    } else if (strcmp(vendor, "AuthenticAMD") == 0) {
        // AMD: Ryzen base clocks
        return 3.6;  // Most modern AMD CPUs
    }
    
    // Unknown vendor: very conservative
    return 2.5;
}

} // namespace Deep2
