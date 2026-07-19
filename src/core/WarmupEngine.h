// ============================================================================
// WarmupEngine.h - Memory Pre-faulting Engine Header
// ============================================================================

#ifndef WARMUP_ENGINE_H
#define WARMUP_ENGINE_H

#include <cstddef>
#include <cstdint>

namespace RawrXD {

class WarmupEngine {
public:
    // Pre-fault memory pages by touching them
    static bool PreFault(void* baseAddr, size_t sizeBytes);
    
    // Parallel pre-fault using multiple threads
    static bool PreFaultParallel(void* baseAddr, size_t sizeBytes, int numThreads = 4);
    
    // Lock pages in physical memory (requires SeLockMemoryPrivilege)
    static bool LockPages(void* baseAddr, size_t sizeBytes);
    
    // Full warmup sequence: pre-fault + optional lock
    static bool Warmup(void* baseAddr, size_t sizeBytes, bool useParallel = true, bool tryLock = false);
    
    // Check if memory is resident (diagnostic)
    static size_t CheckResidency(void* baseAddr, size_t sizeBytes);
};

} // namespace RawrXD

// C Interface
extern "C" {
    __declspec(dllexport) bool WarmupEngine_PreFault(void* baseAddr, size_t sizeBytes);
    __declspec(dllexport) bool WarmupEngine_Warmup(void* baseAddr, size_t sizeBytes);
    __declspec(dllexport) size_t WarmupEngine_CheckResidency(void* baseAddr, size_t sizeBytes);
}

#endif // WARMUP_ENGINE_H
