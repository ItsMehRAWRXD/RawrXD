// ============================================================================
// Deep2_WarmupEngine.h - Memory Warmup Engine for Deep2 Inference
// Pre-faults memory pages to ensure model weights stay resident in RAM
// Eliminates page fault penalties during inference
// ============================================================================

#ifndef DEEP2_WARMUP_ENGINE_H
#define DEEP2_WARMUP_ENGINE_H

#include <cstddef>
#include <cstdint>

namespace Deep2 {

// Warmup strategy flags
enum class WarmupStrategy {
    SEQUENTIAL_TOUCH = 0,    // Touch each page sequentially (best for HDD)
    PARALLEL_TOUCH = 1,      // Touch pages in parallel threads (best for NVMe)
    SIMD_PREFETCH = 2,       // Use AVX prefetch instructions
    ADAPTIVE = 3             // Auto-detect based on hardware
};

// Warmup engine configuration
struct WarmupConfig {
    WarmupStrategy strategy;
    size_t pageSize;         // Usually 4096 bytes
    size_t prefetchDistance; // Pages to prefetch ahead
    size_t threadCount;      // For parallel warmup
    bool useLargePages;      // Use MEM_LARGE_PAGES if available
    
    WarmupConfig() 
        : strategy(WarmupStrategy::ADAPTIVE)
        , pageSize(4096)
        , prefetchDistance(8)
        , threadCount(4)
        , useLargePages(false) {}
};

// Warmup statistics
struct WarmupStats {
    size_t totalPages;
    size_t pagesTouched;
    double elapsedMs;
    double bandwidthGBps;
    bool success;
};

// ============================================================================
// WarmupEngine Class
// Ensures model weights are resident in physical memory before inference
// ============================================================================
class WarmupEngine {
public:
    WarmupEngine();
    ~WarmupEngine();
    
    // Initialize with configuration
    bool Initialize(const WarmupConfig& config);
    
    // Warm up memory region - ensures all pages are resident
    WarmupStats WarmupRegion(void* baseAddress, size_t size);
    
    // Warm up with specific strategy
    WarmupStats WarmupRegion(void* baseAddress, size_t size, WarmupStrategy strategy);
    
    // Check if region is resident (diagnostic)
    size_t CheckResidency(void* baseAddress, size_t size);
    
    // Lock pages in memory (prevent swapping)
    bool LockPages(void* baseAddress, size_t size);
    bool UnlockPages(void* baseAddress, size_t size);
    
    // Get last error
    const char* GetLastError() const { return m_lastError; }
    
private:
    WarmupConfig m_config;
    char m_lastError[256];
    bool m_initialized;
    
    // Internal implementation
    WarmupStats SequentialTouch(void* baseAddress, size_t size);
    WarmupStats ParallelTouch(void* baseAddress, size_t size);
    WarmupStats SIMDPrefetch(void* baseAddress, size_t size);
    
    // Touch a single page (force allocation)
    static inline void TouchPage(volatile char* page) {
        *page = *page;  // Read-write to force page fault
    }
};

// ============================================================================
// C Interface for integration with C++ and MASM code
// ============================================================================
extern "C" {
    // Create/destroy warmup engine
    void* Deep2_WarmupEngine_Create();
    void Deep2_WarmupEngine_Destroy(void* engine);
    
    // Initialize
    int Deep2_WarmupEngine_Init(void* engine, const WarmupConfig* config);
    
    // Warmup region
    int Deep2_WarmupEngine_Warmup(void* engine, void* baseAddress, size_t size);
    
    // Lock/unlock pages
    int Deep2_WarmupEngine_Lock(void* engine, void* baseAddress, size_t size);
    int Deep2_WarmupEngine_Unlock(void* engine, void* baseAddress, size_t size);
}

} // namespace Deep2

#endif // DEEP2_WARMUP_ENGINE_H
