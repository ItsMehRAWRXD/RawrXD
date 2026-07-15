#include "rawrxd/core.hpp"
#include "config_manager.hpp"
#include "version.hpp"

#include <iostream>
#include <mutex>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#else
#include <unistd.h>
#include <sys/sysinfo.h>
#endif

namespace RawrXD {

namespace {
    // Global state
    std::mutex g_initMutex;
    bool g_initialized = false;
    std::string g_lastError;
    
    // Configuration
    std::unique_ptr<Core::ConfigManager> g_config;
}

bool Initialize(const char* configPath) {
    std::lock_guard<std::mutex> lock(g_initMutex);
    
    if (g_initialized) {
        return true;
    }
    
    try {
        // Initialize configuration
        g_config = std::make_unique<Core::ConfigManager>();
        
        if (configPath && std::strlen(configPath) > 0) {
            if (!g_config->Initialize(configPath)) {
                g_lastError = "Failed to load configuration from: " + std::string(configPath);
                return false;
            }
        } else {
            if (!g_config->Initialize()) {
                g_lastError = "Failed to initialize default configuration";
                return false;
            }
        }
        
        // Set global config
        Core::SetGlobalConfig(std::move(g_config));
        
        g_initialized = true;
        
        // Print startup banner
        std::cout << "RawrXD Sovereign Inferencer v" << GetCurrentVersion().ToString() << "\n";
        std::cout << "================================\n";
        
        return true;
        
    } catch (const std::exception& e) {
        g_lastError = std::string("Initialization error: ") + e.what();
        return false;
    }
}

void Shutdown() {
    std::lock_guard<std::mutex> lock(g_initMutex);
    
    if (!g_initialized) {
        return;
    }
    
    // Reset global config
    Core::ResetGlobalConfig();
    
    g_initialized = false;
}

bool IsInitialized() {
    std::lock_guard<std::mutex> lock(g_initMutex);
    return g_initialized;
}

const char* GetLastError() {
    std::lock_guard<std::mutex> lock(g_initMutex);
    return g_lastError.empty() ? nullptr : g_lastError.c_str();
}

SystemInfo GetSystemInfo() {
    SystemInfo info{};
    
    info.platform = RAWRXD_PLATFORM_NAME;
    info.architecture = RAWRXD_ARCH_NAME;
    info.compiler = RAWRXD_COMPILER_NAME;
    info.compilerVersion = RAWRXD_COMPILER_VERSION;
    
    // CPU count
#ifdef _WIN32
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    info.cpuCount = sysInfo.dwNumberOfProcessors;
#else
    info.cpuCount = sysconf(_SC_NPROCESSORS_ONLN);
#endif
    
    // Physical memory
#ifdef _WIN32
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    info.physicalMemory = memStatus.ullTotalPhys;
#else
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        info.physicalMemory = si.totalram * si.mem_unit;
    }
#endif
    
    // CPU features
#if defined(_WIN32) && (defined(_M_X64) || defined(_M_IX86))
    int cpuInfo[4] = {0};
    
    // Check max function
    __cpuid(cpuInfo, 0);
    int maxFunction = cpuInfo[0];
    
    if (maxFunction >= 1) {
        __cpuid(cpuInfo, 1);
        info.hasAVX = (cpuInfo[2] & (1 << 28)) != 0;  // ECX bit 28
        info.hasFMA = (cpuInfo[2] & (1 << 12)) != 0;  // ECX bit 12
    }
    
    if (maxFunction >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        info.hasAVX2 = (cpuInfo[1] & (1 << 5)) != 0;   // EBX bit 5
        info.hasAVX512 = (cpuInfo[1] & (1 << 16)) != 0; // EBX bit 16
    }
#elif defined(__x86_64__) || defined(__i386__)
    // Linux CPU feature detection would go here
    // For now, leave as false
    info.hasAVX = false;
    info.hasAVX2 = false;
    info.hasAVX512 = false;
    info.hasFMA = false;
#endif
    
    return info;
}

void PrintSystemInfo() {
    SystemInfo info = GetSystemInfo();
    
    std::cout << "System Information:\n";
    std::cout << "  Platform:     " << info.platform << "\n";
    std::cout << "  Architecture: " << info.architecture << "\n";
    std::cout << "  Compiler:     " << info.compiler << " " << info.compilerVersion << "\n";
    std::cout << "  CPU Cores:    " << info.cpuCount << "\n";
    std::cout << "  Memory:       " << (info.physicalMemory / (1024 * 1024 * 1024)) << " GB\n";
    std::cout << "  Features:     ";
    if (info.hasAVX) std::cout << "AVX ";
    if (info.hasAVX2) std::cout << "AVX2 ";
    if (info.hasAVX512) std::cout << "AVX-512 ";
    if (info.hasFMA) std::cout << "FMA ";
    std::cout << "\n";
}

FeatureFlags GetFeatureFlags() {
    FeatureFlags flags{};
    
    // These would be set based on actual build configuration
#ifdef RAWRXD_ENABLE_VULKAN
    flags.hasVulkan = true;
#endif
#ifdef RAWRXD_ENABLE_CUDA
    flags.hasCUDA = true;
#endif
#ifdef RAWRXD_ENABLE_ROCM
    flags.hasROCm = true;
#endif
#ifdef RAWRXD_ENABLE_OPENCL
    flags.hasOpenCL = true;
#endif
#ifdef RAWRXD_ENABLE_METAL
    flags.hasMetal = true;
#endif
#ifdef RAWRXD_ENABLE_MASM
    flags.hasMASM = true;
#endif
#ifdef RAWRXD_ENABLE_FLASH_ATTENTION
    flags.hasFlashAttention = true;
#endif
#ifdef RAWRXD_ENABLE_SPECULATIVE
    flags.hasSpeculativeDecoding = true;
#endif
    
    return flags;
}

void PrintFeatureFlags() {
    FeatureFlags flags = GetFeatureFlags();
    
    std::cout << "Feature Flags:\n";
    std::cout << "  Vulkan:               " << (flags.hasVulkan ? "Yes" : "No") << "\n";
    std::cout << "  CUDA:                 " << (flags.hasCUDA ? "Yes" : "No") << "\n";
    std::cout << "  ROCm:                 " << (flags.hasROCm ? "Yes" : "No") << "\n";
    std::cout << "  OpenCL:               " << (flags.hasOpenCL ? "Yes" : "No") << "\n";
    std::cout << "  Metal:                " << (flags.hasMetal ? "Yes" : "No") << "\n";
    std::cout << "  MASM:                 " << (flags.hasMASM ? "Yes" : "No") << "\n";
    std::cout << "  Flash Attention:      " << (flags.hasFlashAttention ? "Yes" : "No") << "\n";
    std::cout << "  Speculative Decoding: " << (flags.hasSpeculativeDecoding ? "Yes" : "No") << "\n";
}

MemoryStats GetMemoryStats() {
    // Placeholder - would integrate with actual memory tracker
    MemoryStats stats{};
    return stats;
}

void PrintMemoryStats() {
    MemoryStats stats = GetMemoryStats();
    
    std::cout << "Memory Statistics:\n";
    std::cout << "  Total Allocated:  " << stats.totalAllocated << " bytes\n";
    std::cout << "  Total Freed:      " << stats.totalFreed << " bytes\n";
    std::cout << "  Current Usage:    " << stats.currentUsage << " bytes\n";
    std::cout << "  Peak Usage:       " << stats.peakUsage << " bytes\n";
    std::cout << "  Allocations:      " << stats.allocationCount << "\n";
    std::cout << "  Frees:            " << stats.freeCount << "\n";
}

// ScopedInit implementation
ScopedInit::ScopedInit(const char* configPath)
    : initialized_(Initialize(configPath))
    , shouldShutdown_(initialized_) {
}

ScopedInit::~ScopedInit() {
    if (shouldShutdown_) {
        Shutdown();
    }
}

ScopedInit::ScopedInit(ScopedInit&& other) noexcept
    : initialized_(other.initialized_)
    , shouldShutdown_(other.shouldShutdown_) {
    other.shouldShutdown_ = false;
}

ScopedInit& ScopedInit::operator=(ScopedInit&& other) noexcept {
    if (this != &other) {
        if (shouldShutdown_) {
            Shutdown();
        }
        initialized_ = other.initialized_;
        shouldShutdown_ = other.shouldShutdown_;
        other.shouldShutdown_ = false;
    }
    return *this;
}

} // namespace RawrXD

// C interface
extern "C" {

int RawrXD_Initialize(const char* configPath) {
    return RawrXD::Initialize(configPath) ? 0 : 1;
}

void RawrXD_Shutdown(void) {
    RawrXD::Shutdown();
}

int RawrXD_IsInitialized(void) {
    return RawrXD::IsInitialized() ? 1 : 0;
}

}
