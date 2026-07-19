// ============================================================================
// WarmupEngine.cpp - Memory Pre-faulting Engine
// Forces OS to allocate physical RAM for memory-mapped model weights
// Eliminates page fault overhead during inference
// ============================================================================

#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <thread>
#include <vector>

namespace RawrXD {

// ============================================================================
// WarmupEngine - Pre-faults memory pages to keep them resident
// ============================================================================
class WarmupEngine {
public:
    // Pre-fault memory pages by touching them
    // This forces OS to allocate physical RAM
    static bool PreFault(void* baseAddr, size_t sizeBytes) {
        if (!baseAddr || sizeBytes == 0) {
            return false;
        }

        printf("[WarmupEngine] Pre-faulting %zu MB...\n", sizeBytes / (1024 * 1024));
        
        // Touch every page (4KB) to force allocation
        // Use volatile to prevent compiler optimization
        volatile char* ptr = (volatile char*)baseAddr;
        const size_t pageSize = 4096;
        size_t numPages = (sizeBytes + pageSize - 1) / pageSize;
        
        // Touch each page - this triggers page fault and physical allocation
        for (size_t i = 0; i < numPages; i++) {
            ptr[i * pageSize] = 0;  // Touch first byte of each page
        }
        
        printf("[WarmupEngine] Pre-fault complete: %zu pages touched\n", numPages);
        return true;
    }

    // Parallel pre-fault using multiple threads
    static bool PreFaultParallel(void* baseAddr, size_t sizeBytes, int numThreads = 4) {
        if (!baseAddr || sizeBytes == 0) {
            return false;
        }

        printf("[WarmupEngine] Parallel pre-faulting %zu MB with %d threads...\n", 
               sizeBytes / (1024 * 1024), numThreads);

        const size_t pageSize = 4096;
        size_t numPages = (sizeBytes + pageSize - 1) / pageSize;
        size_t pagesPerThread = numPages / numThreads;
        
        std::vector<std::thread> threads;
        volatile char* basePtr = (volatile char*)baseAddr;
        
        // Launch threads to touch pages in parallel
        for (int t = 0; t < numThreads; t++) {
            size_t startPage = t * pagesPerThread;
            size_t endPage = (t == numThreads - 1) ? numPages : (t + 1) * pagesPerThread;
            
            threads.emplace_back([basePtr, startPage, endPage, pageSize]() {
                for (size_t i = startPage; i < endPage; i++) {
                    basePtr[i * pageSize] = 0;
                }
            });
        }
        
        // Wait for all threads
        for (auto& th : threads) {
            th.join();
        }
        
        printf("[WarmupEngine] Parallel pre-fault complete: %zu pages touched\n", numPages);
        return true;
    }

    // Lock pages in physical memory (requires SeLockMemoryPrivilege)
    static bool LockPages(void* baseAddr, size_t sizeBytes) {
        if (!baseAddr || sizeBytes == 0) {
            return false;
        }

        // Try to lock pages in working set
        // This prevents them from being paged out
        BOOL result = VirtualLock(baseAddr, sizeBytes);
        
        if (result) {
            printf("[WarmupEngine] Locked %zu MB in physical memory\n", 
                   sizeBytes / (1024 * 1024));
            return true;
        } else {
            DWORD error = GetLastError();
            printf("[WarmupEngine] VirtualLock failed (error %lu) - may need SeLockMemoryPrivilege\n", error);
            // Continue anyway - pre-fault still helps
            return false;
        }
    }

    // Full warmup sequence: pre-fault + optional lock
    static bool Warmup(void* baseAddr, size_t sizeBytes, bool useParallel = true, bool tryLock = false) {
        if (!baseAddr || sizeBytes == 0) {
            return false;
        }

        printf("[WarmupEngine] Starting warmup for %zu MB...\n", sizeBytes / (1024 * 1024));
        
        auto startTime = GetTickCount64();
        
        // Step 1: Pre-fault pages
        bool result;
        if (useParallel && sizeBytes > 100 * 1024 * 1024) {  // Use parallel for >100MB
            result = PreFaultParallel(baseAddr, sizeBytes);
        } else {
            result = PreFault(baseAddr, sizeBytes);
        }
        
        if (!result) {
            return false;
        }
        
        // Step 2: Optionally lock pages
        if (tryLock) {
            LockPages(baseAddr, sizeBytes);
        }
        
        auto elapsedMs = GetTickCount64() - startTime;
        printf("[WarmupEngine] Warmup complete in %llu ms\n", elapsedMs);
        
        return true;
    }

    // Check if memory is resident (diagnostic)
    static size_t CheckResidency(void* baseAddr, size_t sizeBytes) {
        if (!baseAddr || sizeBytes == 0) {
            return 0;
        }

        // Query working set information
        PSAPI_WORKING_SET_EX_INFORMATION wsInfo;
        wsInfo.VirtualAddress = baseAddr;
        
        size_t residentPages = 0;
        const size_t pageSize = 4096;
        size_t numPages = (sizeBytes + pageSize - 1) / pageSize;
        
        // Sample every 100th page for performance
        for (size_t i = 0; i < numPages; i += 100) {
            wsInfo.VirtualAddress = (char*)baseAddr + i * pageSize;
            if (QueryWorkingSetEx(GetCurrentProcess(), &wsInfo, sizeof(wsInfo))) {
                if (wsInfo.VirtualAttributes.Valid) {
                    residentPages++;
                }
            }
        }
        
        size_t sampledPages = (numPages + 99) / 100;
        size_t estimatedResident = residentPages * 100;
        
        printf("[WarmupEngine] Residency check: ~%zu/%zu pages resident (%.1f%%)\n",
               estimatedResident, numPages, 
               (double)estimatedResident / numPages * 100);
        
        return estimatedResident * pageSize;
    }
};

} // namespace RawrXD

// ============================================================================
// C Interface for integration
// ============================================================================
extern "C" {

__declspec(dllexport) bool WarmupEngine_PreFault(void* baseAddr, size_t sizeBytes) {
    return RawrXD::WarmupEngine::PreFault(baseAddr, sizeBytes);
}

__declspec(dllexport) bool WarmupEngine_Warmup(void* baseAddr, size_t sizeBytes) {
    return RawrXD::WarmupEngine::Warmup(baseAddr, sizeBytes, true, false);
}

__declspec(dllexport) size_t WarmupEngine_CheckResidency(void* baseAddr, size_t sizeBytes) {
    return RawrXD::WarmupEngine::CheckResidency(baseAddr, sizeBytes);
}

}
