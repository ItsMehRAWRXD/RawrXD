// =============================================================================
// sovereign_async_telemetry.cpp
// Non-blocking Telemetry Logger for Production Deployment
//
// Phase 16A: Ensures telemetry never blocks the inference loop
// Strategy: Lock-free ring buffer + dedicated writer thread
// =============================================================================

#include "sovereign_async_telemetry.h"
#include <windows.h>
#include <atomic>
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstring>

// =============================================================================
// Configuration
// =============================================================================

#define TELEMETRY_BUFFER_SIZE       16384   // 16K entries
#define TELEMETRY_FLUSH_INTERVAL_MS 1000    // Flush every 1 second
#define TELEMETRY_MAX_FILE_SIZE_MB  100    // Rotate after 100MB
#define TELEMETRY_WRITE_BATCH       64     // Write 64 entries at a time

// =============================================================================
// Lock-Free Ring Buffer
// =============================================================================

template<typename T, size_t Size>
class LockFreeRingBuffer {
private:
    alignas(64) std::atomic<size_t> head{0};  // Write position
    alignas(64) std::atomic<size_t> tail{0};  // Read position
    T buffer[Size];
    
public:
    static_assert((Size & (Size - 1)) == 0, "Size must be power of 2");
    
    bool Push(const T& item) {
        size_t currentHead = head.load(std::memory_order_relaxed);
        size_t nextHead = (currentHead + 1) & (Size - 1);
        
        // Check if full
        if (nextHead == tail.load(std::memory_order_acquire)) {
            return false;  // Buffer full
        }
        
        buffer[currentHead] = item;
        head.store(nextHead, std::memory_order_release);
        return true;
    }
    
    bool Pop(T& item) {
        size_t currentTail = tail.load(std::memory_order_relaxed);
        
        // Check if empty
        if (currentTail == head.load(std::memory_order_acquire)) {
            return false;  // Buffer empty
        }
        
        item = buffer[currentTail];
        tail.store((currentTail + 1) & (Size - 1), std::memory_order_release);
        return true;
    }
    
    size_t Size() const {
        return (head.load(std::memory_order_relaxed) - 
                tail.load(std::memory_order_relaxed)) & (Size - 1);
    }
    
    bool IsEmpty() const {
        return head.load(std::memory_order_acquire) == 
               tail.load(std::memory_order_acquire);
    }
    
    bool IsFull() const {
        return ((head.load(std::memory_order_relaxed) + 1) & (Size - 1)) ==
                tail.load(std::memory_order_relaxed);
    }
};

// =============================================================================
// Telemetry Entry
// =============================================================================

struct TelemetryEntry {
    uint64_t timestamp;      // Microseconds since epoch
    uint32_t eventType;    // Event type ID
    uint32_t sessionId;    // Session identifier
    float latencyMs;       // Event latency
    uint32_t data1;        // Event-specific data
    uint32_t data2;        // Event-specific data
    
    // Serialize to JSON
    std::string ToJson() const {
        char buf[512];
        snprintf(buf, sizeof(buf),
                 "{\"ts\":%llu,\"type\":%u,\"session\":%u,\"lat\":%.3f,\"d1\":%u,\"d2\":%u}",
                 timestamp, eventType, sessionId, latencyMs, data1, data2);
        return std::string(buf);
    }
};

// =============================================================================
// Async Telemetry Logger
// =============================================================================

class AsyncTelemetryLogger {
private:
    LockFreeRingBuffer<TelemetryEntry, TELEMETRY_BUFFER_SIZE> ringBuffer;
    std::thread writerThread;
    std::atomic<bool> running{false};
    std::atomic<bool> flushRequested{false};
    
    char logFilePath[MAX_PATH];
    FILE* logFile;
    uint64_t currentFileSize;
    
    // Event type names for human-readable logs
    const char* GetEventName(uint32_t type) {
        switch (type) {
            case 1: return "TRIGGER";
            case 2: return "FIRST_TOKEN";
            case 3: return "TOKEN_STREAM";
            case 4: return "COMPLETION_DONE";
            case 5: return "CANCEL";
            case 6: return "ERROR";
            case 7: return "MMAP_FAULT";
            case 8: return "KV_CACHE_HIT";
            case 9: return "KV_CACHE_MISS";
            default: return "UNKNOWN";
        }
    }
    
    void WriterThreadFunc() {
        // Set thread priority lower than inference
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        
        TelemetryEntry batch[TELEMETRY_WRITE_BATCH];
        int batchCount = 0;
        
        auto lastFlush = std::chrono::steady_clock::now();
        
        while (running) {
            // Try to fill batch
            while (batchCount < TELEMETRY_WRITE_BATCH) {
                TelemetryEntry entry;
                if (!ringBuffer.Pop(entry)) {
                    break;  // No more entries
                }
                batch[batchCount++] = entry;
            }
            
            // Write batch if full or flush requested
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - lastFlush).count();
            
            if (batchCount >= TELEMETRY_WRITE_BATCH || 
                (batchCount > 0 && elapsed >= TELEMETRY_FLUSH_INTERVAL_MS) ||
                flushRequested.load()) {
                
                WriteBatch(batch, batchCount);
                batchCount = 0;
                lastFlush = now;
                flushRequested.store(false);
            }
            
            // Small sleep to prevent busy-waiting
            if (batchCount == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        
        // Flush remaining entries on shutdown
        while (batchCount < TELEMETRY_WRITE_BATCH) {
            TelemetryEntry entry;
            if (!ringBuffer.Pop(entry)) break;
            batch[batchCount++] = entry;
        }
        if (batchCount > 0) {
            WriteBatch(batch, batchCount);
        }
    }
    
    void WriteBatch(TelemetryEntry* batch, int count) {
        if (!logFile || count == 0) return;
        
        // Write each entry
        for (int i = 0; i < count; i++) {
            std::string json = batch[i].ToJson();
            fprintf(logFile, "%s\n", json.c_str());
            currentFileSize += json.length() + 1;
        }
        
        // Periodic flush to disk (not every write for performance)
        static int writeCounter = 0;
        if (++writeCounter >= 10) {
            fflush(logFile);
            writeCounter = 0;
        }
        
        // Check for file rotation
        if (currentFileSize > TELEMETRY_MAX_FILE_SIZE_MB * 1024 * 1024) {
            RotateLogFile();
        }
    }
    
    void RotateLogFile() {
        if (logFile) {
            fclose(logFile);
        }
        
        // Rename current file with timestamp
        char newPath[MAX_PATH];
        SYSTEMTIME st;
        GetSystemTime(&st);
        snprintf(newPath, sizeof(newPath), "%s.%04d%02d%02d_%02d%02d%02d",
                 logFilePath, st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond);
        
        MoveFileA(logFilePath, newPath);
        
        // Open new file
        logFile = fopen(logFilePath, "a");
        currentFileSize = 0;
    }
    
public:
    AsyncTelemetryLogger() : logFile(nullptr), currentFileSize(0) {}
    
    ~AsyncTelemetryLogger() {
        Shutdown();
    }
    
    bool Initialize(const char* logPath) {
        strncpy(logFilePath, logPath, MAX_PATH - 1);
        logFilePath[MAX_PATH - 1] = '\0';
        
        // Open log file
        logFile = fopen(logPath, "a");
        if (!logFile) {
            return false;
        }
        
        // Get current file size
        fseek(logFile, 0, SEEK_END);
        currentFileSize = ftell(logFile);
        
        // Start writer thread
        running = true;
        writerThread = std::thread(&AsyncTelemetryLogger::WriterThreadFunc, this);
        
        return true;
    }
    
    void Shutdown() {
        if (!running) return;
        
        running = false;
        if (writerThread.joinable()) {
            writerThread.join();
        }
        
        if (logFile) {
            fclose(logFile);
            logFile = nullptr;
        }
    }
    
    // Non-blocking log call - returns immediately
    bool Log(uint32_t eventType, uint32_t sessionId, 
             float latencyMs, uint32_t data1 = 0, uint32_t data2 = 0) {
        TelemetryEntry entry;
        entry.timestamp = GetTimestampMicros();
        entry.eventType = eventType;
        entry.sessionId = sessionId;
        entry.latencyMs = latencyMs;
        entry.data1 = data1;
        entry.data2 = data2;
        
        // Try to push to ring buffer (non-blocking)
        if (!ringBuffer.Push(entry)) {
            // Buffer full - telemetry dropped (rare, but prevents blocking)
            return false;
        }
        
        return true;
    }
    
    void RequestFlush() {
        flushRequested.store(true);
    }
    
    size_t GetBufferUtilization() const {
        return ringBuffer.Size();
    }
    
    bool IsBufferFull() const {
        return ringBuffer.IsFull();
    }
    
private:
    uint64_t GetTimestampMicros() {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        return (uli.QuadPart / 10) - 11644473600000000ULL;
    }
};

// =============================================================================
// Global Instance
// =============================================================================

static AsyncTelemetryLogger g_telemetryLogger;

// =============================================================================
// Public C API
// =============================================================================

extern "C" {

__declspec(dllexport) bool Sovereign_Telemetry_Init(const char* logPath) {
    return g_telemetryLogger.Initialize(logPath);
}

__declspec(dllexport) void Sovereign_Telemetry_Shutdown() {
    g_telemetryLogger.Shutdown();
}

__declspec(dllexport) bool Sovereign_Telemetry_Log(
    uint32_t eventType,
    uint32_t sessionId,
    float latencyMs,
    uint32_t data1,
    uint32_t data2
) {
    return g_telemetryLogger.Log(eventType, sessionId, latencyMs, data1, data2);
}

__declspec(dllexport) void Sovereign_Telemetry_Flush() {
    g_telemetryLogger.RequestFlush();
}

__declspec(dllexport) size_t Sovereign_Telemetry_GetBufferUtilization() {
    return g_telemetryLogger.GetBufferUtilization();
}

__declspec(dllexport) bool Sovereign_Telemetry_IsBufferFull() {
    return g_telemetryLogger.IsBufferFull();
}

} // extern "C"

// =============================================================================
// Usage Example
// =============================================================================

#ifdef TELEMETRY_EXAMPLE

void ExampleUsage() {
    // Initialize
    Sovereign_Telemetry_Init("D:\\RawrXD\\logs\\telemetry.log");
    
    // In inference loop (non-blocking)
    auto start = std::chrono::high_resolution_clock::now();
    
    // ... do inference ...
    
    auto end = std::chrono::high_resolution_clock::now();
    float latency = std::chrono::duration<float, std::milli>(end - start).count();
    
    // Log without blocking
    Sovereign_Telemetry_Log(2,  // FIRST_TOKEN
                           123,  // session ID
                           latency,
                           0, 0);
    
    // Continue immediately - no waiting for disk write
    
    // Shutdown on exit
    Sovereign_Telemetry_Shutdown();
}

#endif // TELEMETRY_EXAMPLE
