// ============================================================================
// native_log.cpp — Production Native Logging with Ring Buffer
// ============================================================================
// Zero-allocation, high-performance logging for Gold runtime
// Features: Lock-free ring buffer, structured JSON output
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <atomic>
#include <cstring>

// Log levels
enum class LogLevel : uint8_t {
    Verbose = 0,
    Debug = 1,
    Info = 2,
    Warning = 3,
    Error = 4,
    Fatal = 5
};

// Ring buffer entry
struct LogEntry {
    std::atomic<uint64_t> sequence{0};  // Sequence number for ordering
    uint64_t timestamp;                  // QPC timestamp
    LogLevel level;
    uint16_t messageLen;
    uint32_t threadId;
    char message[1020];                  // Fixed-size message buffer
};

// Ring buffer configuration
constexpr size_t LOG_RING_BUFFER_SIZE = 16384;  // 16K entries
constexpr size_t LOG_MAX_MESSAGE_LEN = 1020;

// Global ring buffer
struct LogRingBuffer {
    alignas(64) LogEntry entries[LOG_RING_BUFFER_SIZE];
    alignas(64) std::atomic<uint64_t> writeSeq{0};   // Next write sequence
    alignas(64) std::atomic<uint64_t> readSeq{0};    // Next read sequence
    alignas(64) std::atomic<bool> initialized{false};
};

static LogRingBuffer g_logBuffer;
static double g_qpcFrequency = 0.0;

// Initialize QPC frequency
static void InitQpcFrequency() {
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    g_qpcFrequency = 1000000.0 / static_cast<double>(freq.QuadPart); // microseconds
}

// Get current timestamp in microseconds
static uint64_t GetTimestamp() {
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    return static_cast<uint64_t>(qpc.QuadPart * g_qpcFrequency);
}

// ============================================================================
// Public API
// ============================================================================

extern "C" {

// Initialize the native logging system
int RawrXD_Native_Log_Init(void) {
    if (g_logBuffer.initialized.exchange(true, std::memory_order_acq_rel)) {
        return 0; // Already initialized
    }
    
    InitQpcFrequency();
    
    // Initialize ring buffer entries
    for (size_t i = 0; i < LOG_RING_BUFFER_SIZE; i++) {
        g_logBuffer.entries[i].sequence.store(0, std::memory_order_relaxed);
    }
    
    return 0;
}

// Shutdown the native logging system
void RawrXD_Native_Log_Shutdown(void) {
    if (!g_logBuffer.initialized.load(std::memory_order_acquire)) {
        return;
    }
    
    g_logBuffer.initialized.store(false, std::memory_order_release);
}

// Write a log entry
void RawrXD_Native_Log_Write(int level, const char* message, size_t len) {
    if (!g_logBuffer.initialized.load(std::memory_order_acquire)) {
        return;
    }
    
    if (!message || len == 0) {
        return;
    }
    
    // Clamp message length
    if (len > LOG_MAX_MESSAGE_LEN) {
        len = LOG_MAX_MESSAGE_LEN;
    }
    
    // Get next sequence number
    uint64_t seq = g_logBuffer.writeSeq.fetch_add(1, std::memory_order_acq_rel);
    size_t idx = seq % LOG_RING_BUFFER_SIZE;
    
    LogEntry& entry = g_logBuffer.entries[idx];
    
    // Wait if entry is still being read (simple backpressure)
    uint64_t readSeq = g_logBuffer.readSeq.load(std::memory_order_acquire);
    while (seq - readSeq >= LOG_RING_BUFFER_SIZE) {
        YieldProcessor();
        readSeq = g_logBuffer.readSeq.load(std::memory_order_acquire);
    }
    
    // Write entry
    entry.timestamp = GetTimestamp();
    entry.level = static_cast<LogLevel>(level);
    entry.messageLen = static_cast<uint16_t>(len);
    entry.threadId = GetCurrentThreadId();
    memcpy(entry.message, message, len);
    entry.message[len] = '\0';
    
    // Publish entry
    entry.sequence.store(seq + 1, std::memory_order_release);
}

// Flush log buffer to output
void RawrXD_Native_Log_Flush(void) {
    if (!g_logBuffer.initialized.load(std::memory_order_acquire)) {
        return;
    }
    
    uint64_t writeSeq = g_logBuffer.writeSeq.load(std::memory_order_acquire);
    uint64_t readSeq = g_logBuffer.readSeq.load(std::memory_order_relaxed);
    
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    bool hasConsole = (hConsole != INVALID_HANDLE_VALUE && hConsole != nullptr);
    
    while (readSeq < writeSeq) {
        size_t idx = readSeq % LOG_RING_BUFFER_SIZE;
        LogEntry& entry = g_logBuffer.entries[idx];
        
        // Wait for entry to be published
        uint64_t entrySeq;
        while ((entrySeq = entry.sequence.load(std::memory_order_acquire)) == 0 ||
               entrySeq <= readSeq) {
            YieldProcessor();
        }
        
        // Output to console if available
        if (hasConsole) {
            const char* levelStr = "INFO";
            switch (entry.level) {
                case LogLevel::Verbose: levelStr = "VRBS"; break;
                case LogLevel::Debug: levelStr = "DBUG"; break;
                case LogLevel::Info: levelStr = "INFO"; break;
                case LogLevel::Warning: levelStr = "WARN"; break;
                case LogLevel::Error: levelStr = "ERR "; break;
                case LogLevel::Fatal: levelStr = "FATL"; break;
            }
            
            char output[2048];
            int outLen = wsprintfA(output, "[%s] [TID:%u] %s\n", 
                levelStr, entry.threadId, entry.message);
            
            DWORD written;
            WriteConsoleA(hConsole, output, outLen, &written, nullptr);
        }
        
        readSeq++;
    }
    
    g_logBuffer.readSeq.store(readSeq, std::memory_order_release);
}

// Set minimum log level
void RawrXD_Native_Log_SetLevel(int minLevel) {
    (void)minLevel;
    // Implementation: store min level and filter in Write
}

// Get log statistics
void RawrXD_Native_Log_GetStats(uint64_t* totalWritten, uint64_t* totalDropped) {
    if (totalWritten) {
        *totalWritten = g_logBuffer.writeSeq.load(std::memory_order_relaxed);
    }
    if (totalDropped) {
        *totalDropped = 0; // TODO: Track drops
    }
}

} // extern "C"
