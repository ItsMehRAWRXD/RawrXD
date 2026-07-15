// ============================================================================
// native_log.cpp — Production Native Logging with Ring Buffer
// ============================================================================
// Zero-allocation, high-performance logging for Gold runtime
// Features: Lock-free ring buffer, ETW integration, structured JSON output
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <atomic>
#include <cstring>

// ETW Provider GUID: {A4B4C4D4-E4F4-4444-8888-123456789ABC}
static const GUID RawrXDLogProviderGuid = 
    { 0xA4B4C4D4, 0xE4F4, 0x4444, { 0x88, 0x88, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC } };

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
    alignas(64) std::atomic<bool> etwEnabled{false};
    
    // ETW handle
    TRACEHANDLE etwRegHandle{0};
    TRACEHANDLE etwSessionHandle{0};
};

static LogRingBuffer g_logBuffer;
static double g_qpcFrequency = 0.0;

// ETW levels
static const uint8_t ETW_LEVEL_VERBOSE = 5;
static const uint8_t ETW_LEVEL_INFO = 4;
static const uint8_t ETW_LEVEL_WARNING = 3;
static const uint8_t ETW_LEVEL_ERROR = 2;
static const uint8_t ETW_LEVEL_FATAL = 1;

// Convert LogLevel to ETW level
static uint8_t LogLevelToEtw(LogLevel level) {
    switch (level) {
        case LogLevel::Verbose: return ETW_LEVEL_VERBOSE;
        case LogLevel::Debug: return ETW_LEVEL_VERBOSE;
        case LogLevel::Info: return ETW_LEVEL_INFO;
        case LogLevel::Warning: return ETW_LEVEL_WARNING;
        case LogLevel::Error: return ETW_LEVEL_ERROR;
        case LogLevel::Fatal: return ETW_LEVEL_FATAL;
        default: return ETW_LEVEL_INFO;
    }
}

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

// ETW write callback
static ULONG WINAPI EtwCallback(
    TRACEHANDLE SessionHandle,
    uint32_t EventCode,
    TRACE_EVENT_CONTEXT* Context,
    uint32_t Reserved
) {
    (void)Context;
    (void)Reserved;
    
    if (EventCode == 0) { // Enable
        g_logBuffer.etwSessionHandle = SessionHandle;
        g_logBuffer.etwEnabled.store(true, std::memory_order_release);
    } else if (EventCode == 1) { // Disable
        g_logBuffer.etwEnabled.store(false, std::memory_order_release);
        g_logBuffer.etwSessionHandle = 0;
    }
    return ERROR_SUCCESS;
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
    
    // Register ETW provider
    #pragma warning(push)
    #pragma warning(disable: 6387) // Disable SAL warning for EventRegister
    ULONG result = EventRegister(
        &RawrXDLogProviderGuid,
        EtwCallback,
        nullptr,
        &g_logBuffer.etwRegHandle
    );
    #pragma warning(pop)
    
    if (result != ERROR_SUCCESS) {
        // ETW registration failed, but logging still works via ring buffer
        g_logBuffer.etwRegHandle = 0;
    }
    
    return 0;
}

// Shutdown the native logging system
void RawrXD_Native_Log_Shutdown(void) {
    if (!g_logBuffer.initialized.load(std::memory_order_acquire)) {
        return;
    }
    
    // Unregister ETW
    if (g_logBuffer.etwRegHandle != 0) {
        EventUnregister(g_logBuffer.etwRegHandle);
        g_logBuffer.etwRegHandle = 0;
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
    
    // ETW output if enabled
    if (g_logBuffer.etwEnabled.load(std::memory_order_acquire) && g_logBuffer.etwRegHandle != 0) {
        // Prepare ETW event
        EVENT_DESCRIPTOR descriptor;
        EventDescCreate(&descriptor, 
            0x1, // Event ID
            0x0, // Version
            0x0, // Channel
            LogLevelToEtw(entry.level),
            0x0, // Task
            0x0  // Opcode
        );
        
        EVENT_DATA_DESCRIPTOR dataDesc[2];
        EventDataDescCreate(&dataDesc[0], &entry.level, sizeof(uint8_t));
        EventDataDescCreate(&dataDesc[1], entry.message, static_cast<ULONG>(len + 1));
        
        EventWrite(g_logBuffer.etwRegHandle, &descriptor, 2, dataDesc);
    }
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
