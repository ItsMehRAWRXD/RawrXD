#pragma once

/**
 * @file core.hpp
 * @brief RawrXD Core Infrastructure Public API
 * 
 * This header provides the main entry point for RawrXD Core Infrastructure.
 * It includes all essential components for configuration, versioning,
 * and system initialization.
 * 
 * @version 14.7.3
 * @author RawrXD Team
 * @copyright 2024-2025 RawrXD Project
 */

// Version information
#include "core/version.hpp"

// Configuration management
#include "core/config_manager.hpp"

// Platform detection
#if defined(_WIN32)
    #define RAWRXD_PLATFORM_WINDOWS 1
    #define RAWRXD_PLATFORM_NAME "Windows"
#elif defined(__APPLE__)
    #define RAWRXD_PLATFORM_MACOS 1
    #define RAWRXD_PLATFORM_NAME "macOS"
#elif defined(__linux__)
    #define RAWRXD_PLATFORM_LINUX 1
    #define RAWRXD_PLATFORM_NAME "Linux"
#else
    #define RAWRXD_PLATFORM_UNKNOWN 1
    #define RAWRXD_PLATFORM_NAME "Unknown"
#endif

// Architecture detection
#if defined(_M_X64) || defined(__x86_64__)
    #define RAWRXD_ARCH_X64 1
    #define RAWRXD_ARCH_NAME "x64"
#elif defined(_M_ARM64) || defined(__aarch64__)
    #define RAWRXD_ARCH_ARM64 1
    #define RAWRXD_ARCH_NAME "ARM64"
#elif defined(_M_IX86) || defined(__i386__)
    #define RAWRXD_ARCH_X86 1
    #define RAWRXD_ARCH_NAME "x86"
#else
    #define RAWRXD_ARCH_UNKNOWN 1
    #define RAWRXD_ARCH_NAME "Unknown"
#endif

// Compiler detection
#if defined(_MSC_VER)
    #define RAWRXD_COMPILER_MSVC 1
    #define RAWRXD_COMPILER_NAME "MSVC"
    #define RAWRXD_COMPILER_VERSION _MSC_VER
#elif defined(__clang__)
    #define RAWRXD_COMPILER_CLANG 1
    #define RAWRXD_COMPILER_NAME "Clang"
    #define RAWRXD_COMPILER_VERSION (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
#elif defined(__GNUC__)
    #define RAWRXD_COMPILER_GCC 1
    #define RAWRXD_COMPILER_NAME "GCC"
    #define RAWRXD_COMPILER_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#else
    #define RAWRXD_COMPILER_UNKNOWN 1
    #define RAWRXD_COMPILER_NAME "Unknown"
    #define RAWRXD_COMPILER_VERSION 0
#endif

// Export macros
#ifdef _WIN32
    #ifdef RAWRXD_CORE_EXPORTS
        #define RAWRXD_CORE_API __declspec(dllexport)
    #else
        #define RAWRXD_CORE_API __declspec(dllimport)
    #endif
#else
    #define RAWRXD_CORE_API __attribute__((visibility("default")))
#endif

// Namespace documentation
/**
 * @namespace RawrXD
 * @brief Root namespace for all RawrXD components
 */

/**
 * @namespace RawrXD::Core
 * @brief Core infrastructure components
 * 
 * The Core namespace contains fundamental infrastructure including:
 * - Configuration management (@ref ConfigManager)
 * - Version information (@ref Version)
 * - Build information (@ref BuildInfo)
 * - System initialization and shutdown
 */

namespace RawrXD {

/**
 * @brief Initialize the RawrXD core infrastructure
 * 
 * This function must be called before using any other RawrXD functionality.
 * It initializes the configuration system, logging, and other core services.
 * 
 * @param configPath Path to configuration file (optional)
 * @return true if initialization succeeded
 * @return false if initialization failed
 * 
 * @code
 * if (!RawrXD::Initialize("config.json")) {
 *     std::cerr << "Failed to initialize RawrXD\n";
 *     return 1;
 * }
 * @endcode
 */
RAWRXD_CORE_API bool Initialize(const char* configPath = nullptr);

/**
 * @brief Shutdown the RawrXD core infrastructure
 * 
 * This function should be called before program exit to ensure proper
 * cleanup of resources. After calling Shutdown(), no other RawrXD
 * functions should be called.
 */
RAWRXD_CORE_API void Shutdown();

/**
 * @brief Check if RawrXD is initialized
 * 
 * @return true if Initialize() has been called successfully
 * @return false otherwise
 */
RAWRXD_CORE_API bool IsInitialized();

/**
 * @brief Get the last error message
 * 
 * @return const char* Error message or nullptr if no error
 */
RAWRXD_CORE_API const char* GetLastError();

/**
 * @brief System information structure
 */
struct SystemInfo {
    const char* platform;           ///< Platform name
    const char* architecture;       ///< Architecture name
    const char* compiler;           ///< Compiler name
    uint32_t compilerVersion;       ///< Compiler version
    uint64_t physicalMemory;        ///< Physical memory in bytes
    uint32_t cpuCount;              ///< Number of CPU cores
    bool hasAVX;                    ///< AVX support
    bool hasAVX2;                   ///< AVX2 support
    bool hasAVX512;                 ///< AVX-512 support
    bool hasFMA;                    ///< FMA support
};

/**
 * @brief Get system information
 * 
 * @return SystemInfo Structure containing system details
 */
RAWRXD_CORE_API SystemInfo GetSystemInfo();

/**
 * @brief Print system information to stdout
 */
RAWRXD_CORE_API void PrintSystemInfo();

/**
 * @brief Feature flags for optional components
 */
struct FeatureFlags {
    bool hasVulkan;               ///< Vulkan support
    bool hasCUDA;                 ///< CUDA support
    bool hasROCm;                 ///< ROCm/HIP support
    bool hasOpenCL;               ///< OpenCL support
    bool hasMetal;                ///< Metal support (macOS)
    bool hasMASM;                 ///< MASM assembly kernels
    bool hasFlashAttention;       ///< Flash Attention support
    bool hasSpeculativeDecoding;  ///< Speculative decoding
};

/**
 * @brief Get feature flags
 * 
 * @return FeatureFlags Structure containing feature availability
 */
RAWRXD_CORE_API FeatureFlags GetFeatureFlags();

/**
 * @brief Print feature flags to stdout
 */
RAWRXD_CORE_API void PrintFeatureFlags();

/**
 * @brief Memory statistics
 */
struct MemoryStats {
    size_t totalAllocated;        ///< Total memory allocated
    size_t totalFreed;            ///< Total memory freed
    size_t currentUsage;          ///< Current memory usage
    size_t peakUsage;             ///< Peak memory usage
    size_t allocationCount;       ///< Number of allocations
    size_t freeCount;             ///< Number of frees
};

/**
 * @brief Get memory statistics
 * 
 * @return MemoryStats Current memory statistics
 */
RAWRXD_CORE_API MemoryStats GetMemoryStats();

/**
 * @brief Print memory statistics to stdout
 */
RAWRXD_CORE_API void PrintMemoryStats();

/**
 * @brief Scoped initialization helper
 * 
 * This class provides RAII-style initialization of RawrXD.
 * The constructor calls Initialize() and the destructor calls Shutdown().
 * 
 * @code
 * int main() {
 *     RawrXD::ScopedInit init("config.json");
 *     if (!init) {
 *         return 1;
 *     }
 *     
 *     // Use RawrXD...
 *     
 *     return 0; // Shutdown called automatically
 * }
 * @endcode
 */
class RAWRXD_CORE_API ScopedInit {
public:
    /**
     * @brief Construct and initialize RawrXD
     * 
     * @param configPath Path to configuration file
     */
    explicit ScopedInit(const char* configPath = nullptr);
    
    /**
     * @brief Destructor - calls Shutdown()
     */
    ~ScopedInit();
    
    /**
     * @brief Check if initialization succeeded
     * 
     * @return true if initialized successfully
     */
    explicit operator bool() const { return initialized_; }
    
    /**
     * @brief Check if initialization succeeded
     * 
     * @return true if initialized successfully
     */
    bool IsInitialized() const { return initialized_; }
    
    // Non-copyable
    ScopedInit(const ScopedInit&) = delete;
    ScopedInit& operator=(const ScopedInit&) = delete;
    
    // Movable
    ScopedInit(ScopedInit&& other) noexcept;
    ScopedInit& operator=(ScopedInit&& other) noexcept;
    
private:
    bool initialized_;
    bool shouldShutdown_;
};

} // namespace RawrXD

// C-compatible interface
extern "C" {
    /**
     * @brief C-compatible initialization
     * 
     * @param configPath Path to configuration file (can be NULL)
     * @return 0 on success, non-zero on failure
     */
    RAWRXD_CORE_API int RawrXD_Initialize(const char* configPath);
    
    /**
     * @brief C-compatible shutdown
     */
    RAWRXD_CORE_API void RawrXD_Shutdown(void);
    
    /**
     * @brief C-compatible initialization check
     * 
     * @return 1 if initialized, 0 otherwise
     */
    RAWRXD_CORE_API int RawrXD_IsInitialized(void);
}
