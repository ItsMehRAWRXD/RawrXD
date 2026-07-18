// RawrXD Memory Leak Detection
// Phase 8 - Task 14: Memory Leak Detection (Valgrind/ASAN style)

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <unordered_map>

// Allocation tracking structure
struct AllocationInfo {
    void* address;
    size_t size;
    const char* file;
    int line;
    const char* function;
    DWORD threadId;
    ULONGLONG timestamp;
    bool freed;
};

// Memory leak detector
class MemoryLeakDetector {
private:
    std::unordered_map<void*, AllocationInfo> allocations;
    CRITICAL_SECTION cs;
    size_t totalAllocated;
    size_t totalFreed;
    size_t peakUsage;
    bool trackingEnabled;
    
    // Original heap functions
    typedef void* (*MallocFunc)(size_t);
    typedef void (*FreeFunc)(void*);
    typedef void* (*ReallocFunc)(void*, size_t);
    
public:
    MemoryLeakDetector() : totalAllocated(0), totalFreed(0), 
                           peakUsage(0), trackingEnabled(false) {
        InitializeCriticalSection(&cs);
    }
    
    ~MemoryLeakDetector() {
        DeleteCriticalSection(&cs);
    }
    
    void EnableTracking() {
        trackingEnabled = true;
    }
    
    void DisableTracking() {
        trackingEnabled = false;
    }
    
    void TrackAllocation(void* ptr, size_t size, const char* file, 
                         int line, const char* func) {
        if (!trackingEnabled || !ptr) return;
        
        EnterCriticalSection(&cs);
        
        AllocationInfo info;
        info.address = ptr;
        info.size = size;
        info.file = file;
        info.line = line;
        info.function = func;
        info.threadId = GetCurrentThreadId();
        info.timestamp = GetTickCount64();
        info.freed = false;
        
        allocations[ptr] = info;
        totalAllocated += size;
        
        size_t currentUsage = totalAllocated - totalFreed;
        if (currentUsage > peakUsage) {
            peakUsage = currentUsage;
        }
        
        LeaveCriticalSection(&cs);
    }
    
    void TrackFree(void* ptr) {
        if (!trackingEnabled || !ptr) return;
        
        EnterCriticalSection(&cs);
        
        auto it = allocations.find(ptr);
        if (it != allocations.end()) {
            if (!it->second.freed) {
                it->second.freed = true;
                totalFreed += it->second.size;
            }
        }
        
        LeaveCriticalSection(&cs);
    }
    
    void PrintReport() {
        EnterCriticalSection(&cs);
        
        printf("\n=== Memory Leak Detection Report ===\n\n");
        printf("Total Allocated: %zu bytes (%.2f MB)\n", 
               totalAllocated, totalAllocated / (1024.0 * 1024.0));
        printf("Total Freed:     %zu bytes (%.2f MB)\n", 
               totalFreed, totalFreed / (1024.0 * 1024.0));
        printf("Current Usage:   %zu bytes (%.2f MB)\n", 
               totalAllocated - totalFreed, 
               (totalAllocated - totalFreed) / (1024.0 * 1024.0));
        printf("Peak Usage:      %zu bytes (%.2f MB)\n\n", 
               peakUsage, peakUsage / (1024.0 * 1024.0));
        
        // Find leaks
        std::vector<AllocationInfo> leaks;
        for (const auto& pair : allocations) {
            if (!pair.second.freed) {
                leaks.push_back(pair.second);
            }
        }
        
        if (leaks.empty()) {
            printf("No memory leaks detected!\n");
        } else {
            printf("MEMORY LEAKS DETECTED: %zu allocations\n\n", leaks.size());
            printf("%-20s %-10s %-30s %s\n", "Address", "Size", "Location", "Thread");
            printf("--------------------------------------------------------------------------------\n");
            
            size_t totalLeaked = 0;
            for (const auto& leak : leaks) {
                printf("%-20p %-10zu %-30s %lu\n",
                       leak.address, leak.size,
                       leak.function ? leak.function : "unknown",
                       leak.threadId);
                totalLeaked += leak.size;
            }
            
            printf("\nTotal leaked: %zu bytes (%.2f MB)\n", 
                   totalLeaked, totalLeaked / (1024.0 * 1024.0));
        }
        
        LeaveCriticalSection(&cs);
    }
    
    void Reset() {
        EnterCriticalSection(&cs);
        allocations.clear();
        totalAllocated = 0;
        totalFreed = 0;
        peakUsage = 0;
        LeaveCriticalSection(&cs);
    }
    
    bool HasLeaks() {
        EnterCriticalSection(&cs);
        bool hasLeaks = false;
        for (const auto& pair : allocations) {
            if (!pair.second.freed) {
                hasLeaks = true;
                break;
            }
        }
        LeaveCriticalSection(&cs);
        return hasLeaks;
    }
};

// Global detector
static MemoryLeakDetector g_LeakDetector;

// Override macros
#define TRACKING_NEW new(__FILE__, __LINE__, __FUNCTION__)
#define TRACKING_DELETE delete

// Placement new for tracking
void* operator new(size_t size, const char* file, int line, const char* func) {
    void* ptr = malloc(size);
    g_LeakDetector.TrackAllocation(ptr, size, file, line, func);
    return ptr;
}

void* operator new[](size_t size, const char* file, int line, const char* func) {
    void* ptr = malloc(size);
    g_LeakDetector.TrackAllocation(ptr, size, file, line, func);
    return ptr;
}

void operator delete(void* ptr) noexcept {
    g_LeakDetector.TrackFree(ptr);
    free(ptr);
}

void operator delete[](void* ptr) noexcept {
    g_LeakDetector.TrackFree(ptr);
    free(ptr);
}

// C API
extern "C" {

void LeakDetector_Enable() {
    g_LeakDetector.EnableTracking();
}

void LeakDetector_Disable() {
    g_LeakDetector.DisableTracking();
}

void LeakDetector_PrintReport() {
    g_LeakDetector.PrintReport();
}

void LeakDetector_Reset() {
    g_LeakDetector.Reset();
}

int LeakDetector_HasLeaks() {
    return g_LeakDetector.HasLeaks() ? 1 : 0;
}

} // extern "C"

// Test functions
void Test_NoLeak() {
    int* arr = new int[100];
    delete[] arr;
}

void Test_Leak() {
    int* arr = new int[100];
    // Intentionally not freed
    (void)arr;
}

void Test_Mixed() {
    int* a = new int[50];
    int* b = new int[50];
    delete[] a;
    // b is leaked
    (void)b;
}

int main() {
    printf("RawrXD Memory Leak Detector\n");
    printf("===========================\n\n");
    
    LeakDetector_Enable();
    
    printf("Test 1: No leak scenario...\n");
    Test_NoLeak();
    
    printf("Test 2: Leak scenario...\n");
    Test_Leak();
    
    printf("Test 3: Mixed scenario...\n");
    Test_Mixed();
    
    LeakDetector_PrintReport();
    
    int hasLeaks = LeakDetector_HasLeaks();
    printf("\nFinal status: %s\n", hasLeaks ? "LEAKS DETECTED" : "NO LEAKS");
    
    return hasLeaks;
}
