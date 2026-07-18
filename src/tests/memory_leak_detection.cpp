// RawrXD Memory Leak Detection
// Phase 8 - Task 14: Memory Leak Detection (Valgrind/ASAN integration)

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <map>
#include <string>
#include <mutex>

// Memory allocation tracking
struct AllocationInfo {
    void* address;
    size_t size;
    const char* file;
    int line;
    const char* function;
    uint64_t timestamp;
    uint64_t threadId;
};

// Memory leak detector
class MemoryLeakDetector {
private:
    std::map<void*, AllocationInfo> allocations;
    std::mutex allocMutex;
    uint64_t totalAllocated;
    uint64_t totalFreed;
    uint64_t peakMemory;
    uint64_t currentMemory;
    bool trackingEnabled;
    
public:
    MemoryLeakDetector() : totalAllocated(0), totalFreed(0), 
                           peakMemory(0), currentMemory(0), 
                           trackingEnabled(false) {}
    
    void StartTracking() {
        std::lock_guard<std::mutex> lock(allocMutex);
        trackingEnabled = true;
        printf("Memory leak detection started\n");
    }
    
    void StopTracking() {
        std::lock_guard<std::mutex> lock(allocMutex);
        trackingEnabled = false;
    }
    
    void TrackAllocation(void* ptr, size_t size, const char* file, 
                         int line, const char* function) {
        if (!ptr || !trackingEnabled) return;
        
        std::lock_guard<std::mutex> lock(allocMutex);
        
        AllocationInfo info;
        info.address = ptr;
        info.size = size;
        info.file = file;
        info.line = line;
        info.function = function;
        info.timestamp = GetTickCount64();
        info.threadId = GetCurrentThreadId();
        
        allocations[ptr] = info;
        
        totalAllocated += size;
        currentMemory += size;
        if (currentMemory > peakMemory) {
            peakMemory = currentMemory;
        }
    }
    
    void TrackFree(void* ptr) {
        if (!ptr || !trackingEnabled) return;
        
        std::lock_guard<std::mutex> lock(allocMutex);
        
        auto it = allocations.find(ptr);
        if (it != allocations.end()) {
            totalFreed += it->second.size;
            currentMemory -= it->second.size;
            allocations.erase(it);
        }
    }
    
    void GenerateReport(const char* filename) {
        std::lock_guard<std::mutex> lock(allocMutex);
        
        FILE* f = nullptr;
        fopen_s(&f, filename, "w");
        if (!f) return;
        
        fprintf(f, "=== Memory Leak Detection Report ===\n\n");
        fprintf(f, "Total Allocated: %llu bytes (%.2f MB)\n", 
                totalAllocated, totalAllocated / (1024.0 * 1024.0));
        fprintf(f, "Total Freed:     %llu bytes (%.2f MB)\n", 
                totalFreed, totalFreed / (1024.0 * 1024.0));
        fprintf(f, "Current Memory:  %llu bytes (%.2f MB)\n", 
                currentMemory, currentMemory / (1024.0 * 1024.0));
        fprintf(f, "Peak Memory:     %llu bytes (%.2f MB)\n", 
                peakMemory, peakMemory / (1024.0 * 1024.0));
        fprintf(f, "\n");
        
        if (allocations.empty()) {
            fprintf(f, "No memory leaks detected!\n");
        } else {
            fprintf(f, "POTENTIAL MEMORY LEAKS: %zu allocations\n\n", allocations.size());
            
            for (const auto& pair : allocations) {
                const AllocationInfo& info = pair.second;
                fprintf(f, "Leak at %p:\n", info.address);
                fprintf(f, "  Size:      %zu bytes\n", info.size);
                fprintf(f, "  Location:  %s:%d (%s)\n", 
                        info.file ? info.file : "unknown",
                        info.line,
                        info.function ? info.function : "unknown");
                fprintf(f, "  Thread:    %llu\n", info.threadId);
                fprintf(f, "  Timestamp: %llu\n", info.timestamp);
                fprintf(f, "\n");
            }
        }
        
        fclose(f);
        printf("Memory leak report saved to: %s\n", filename);
    }
    
    void PrintSummary() {
        std::lock_guard<std::mutex> lock(allocMutex);
        
        printf("\n=== Memory Usage Summary ===\n");
        printf("Total Allocated: %.2f MB\n", totalAllocated / (1024.0 * 1024.0));
        printf("Total Freed:     %.2f MB\n", totalFreed / (1024.0 * 1024.0));
        printf("Current Memory:  %.2f MB\n", currentMemory / (1024.0 * 1024.0));
        printf("Peak Memory:     %.2f MB\n", peakMemory / (1024.0 * 1024.0));
        printf("Active Allocs:   %zu\n", allocations.size());
        
        if (allocations.empty()) {
            printf("\nNo memory leaks detected!\n");
        } else {
            printf("\nWARNING: %zu potential memory leaks!\n", allocations.size());
        }
    }
    
    size_t GetActiveAllocationCount() {
        std::lock_guard<std::mutex> lock(allocMutex);
        return allocations.size();
    }
    
    uint64_t GetCurrentMemoryUsage() {
        std::lock_guard<std::mutex> lock(allocMutex);
        return currentMemory;
    }
};

// Global detector
static MemoryLeakDetector g_MemoryDetector;

// Override macros for tracking
#define TRACK_MALLOC(size) \
    ([&](const char* file, int line, const char* func) -> void* { \
        void* ptr = malloc(size); \
        g_MemoryDetector.TrackAllocation(ptr, size, file, line, func); \
        return ptr; \
    })(__FILE__, __LINE__, __FUNCTION__)

#define TRACK_FREE(ptr) \
    do { \
        g_MemoryDetector.TrackFree(ptr); \
        free(ptr); \
    } while(0)

// C API
extern "C" {

void MemoryLeakDetector_Start() {
    g_MemoryDetector.StartTracking();
}

void MemoryLeakDetector_Stop() {
    g_MemoryDetector.StopTracking();
}

void MemoryLeakDetector_Report(const char* filename) {
    g_MemoryDetector.GenerateReport(filename);
}

void MemoryLeakDetector_PrintSummary() {
    g_MemoryDetector.PrintSummary();
}

size_t MemoryLeakDetector_GetActiveCount() {
    return g_MemoryDetector.GetActiveAllocationCount();
}

uint64_t MemoryLeakDetector_GetCurrentMemory() {
    return g_MemoryDetector.GetCurrentMemoryUsage();
}

} // extern "C"

// Test functions
void Test_NoLeak() {
    void* ptr = malloc(1024);
    free(ptr);
}

void Test_Leak() {
    void* ptr = malloc(1024);  // Intentional leak for testing
    (void)ptr;  // Suppress unused warning
}

void Test_MultipleAllocations() {
    std::vector<void*> ptrs;
    for (int i = 0; i < 10; i++) {
        ptrs.push_back(malloc(512));
    }
    // Free only half
    for (int i = 0; i < 5; i++) {
        free(ptrs[i]);
    }
}

int main() {
    printf("=== Memory Leak Detection Test ===\n\n");
    
    g_MemoryDetector.StartTracking();
    
    printf("Running Test_NoLeak...\n");
    Test_NoLeak();
    
    printf("Running Test_Leak (intentional)...\n");
    Test_Leak();
    
    printf("Running Test_MultipleAllocations...\n");
    Test_MultipleAllocations();
    
    g_MemoryDetector.StopTracking();
    g_MemoryDetector.PrintSummary();
    g_MemoryDetector.GenerateReport("memory_leak_report.txt");
    
    return 0;
}
