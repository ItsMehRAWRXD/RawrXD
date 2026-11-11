// RawrXD-Script Trace Collector
// Generates deterministic fingerprints from execution traces
// Phase 1: Bug Classification Infrastructure

#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>
#include <string>

namespace RawrXD {
namespace Script {

// Trace event types
enum class TraceEventType : uint8_t {
    OpcodeDispatch = 0,     // PC + Opcode
    RegisterRead = 1,       // Register index + value hash
    RegisterWrite = 2,      // Register index + value hash
    BranchTaken = 3,        // Source PC + Target PC
    BranchNotTaken = 4,     // Source PC + Fallthrough PC
    CallNative = 5,         // Function index
    Return = 6,             // Return value hash
    MemoryAccess = 7,       // Address + operation
    CoverageUpdate = 8,     // Opcode index
    Checkpoint = 9          // Explicit sync point
};

// Compact trace event (16 bytes)
struct alignas(16) TraceEvent {
    uint64_t data;          // Event-specific data (PC, register value, etc.)
    uint32_t timestamp;     // Instruction counter (monotonic)
    uint16_t type;          // TraceEventType
    uint16_t reserved;      // Padding / flags
};

// FNV-1a 64-bit hash constants
constexpr uint64_t FNV_OFFSET_BASIS = 0xcbf29ce484222325ULL;
constexpr uint64_t FNV_PRIME = 0x100000001b3ULL;

// Rolling hash state
struct HashState {
    uint64_t value;
    
    HashState() : value(FNV_OFFSET_BASIS) {}
    
    void update(uint64_t data) {
        // FNV-1a hash
        value ^= data;
        value *= FNV_PRIME;
    }
    
    void update(uint32_t data) {
        update(static_cast<uint64_t>(data));
    }
    
    void update(uint8_t data) {
        update(static_cast<uint64_t>(data));
    }
    
    void update(const void* ptr, size_t len) {
        const uint8_t* bytes = static_cast<const uint8_t*>(ptr);
        for (size_t i = 0; i < len; i++) {
            update(bytes[i]);
        }
    }
    
    uint64_t finalize() const { return value; }
};

// Circular trace buffer configuration
constexpr size_t TRACE_BUFFER_SIZE = 4096;  // 4096 events = 64KB
constexpr size_t TRACE_MASK = TRACE_BUFFER_SIZE - 1;

// Trace fingerprint (128-bit for collision resistance)
struct TraceFingerprint {
    uint64_t hash_a;  // Primary FNV hash
    uint64_t hash_b;  // Secondary (different seed)
    uint32_t event_count;
    uint32_t instruction_count;
    
    bool operator==(const TraceFingerprint& other) const {
        return hash_a == other.hash_a && hash_b == other.hash_b;
    }
    
    bool operator!=(const TraceFingerprint& other) const {
        return !(*this == other);
    }
    
    std::string toString() const;
};

// Global trace buffer (shared with MASM)
// Layout: [TraceEvent array] + [head index] + [tail index] + [instruction counter]
struct TraceBuffer {
    alignas(64) TraceEvent events[TRACE_BUFFER_SIZE];
    volatile uint64_t head;           // Write position (MASM writes here)
    volatile uint64_t tail;           // Read position (C++ reads here)
    volatile uint64_t instruction_counter;  // Monotonic instruction count
    volatile uint32_t active;         // 1 = tracing enabled, 0 = disabled
    
    void reset() {
        head = 0;
        tail = 0;
        instruction_counter = 0;
        active = 1;
        memset(events, 0, sizeof(events));
    }
    
    // Called from MASM via C wrapper
    void push_event(uint64_t data, uint16_t type);
};

// Global trace buffer instance (extern for MASM access)
extern TraceBuffer g_trace_buffer;

// Trace Collector API
class TraceCollector {
public:
    TraceCollector();
    ~TraceCollector();
    
    // Control
    void start();
    void stop();
    void reset();
    bool isActive() const { return buffer_.active != 0; }
    
    // Event recording (called from interpreter)
    void recordOpcode(uint64_t pc, uint8_t opcode);
    void recordRegisterRead(uint8_t reg, uint64_t value);
    void recordRegisterWrite(uint8_t reg, uint64_t value);
    void recordBranch(uint64_t src_pc, uint64_t dst_pc, bool taken);
    void recordCallNative(uint32_t func_idx);
    void recordReturn(uint64_t value);
    
    // Fingerprint generation
    TraceFingerprint generateFingerprint();
    
    // Analysis
    size_t getEventCount() const;
    std::string getTraceSummary() const;
    void dumpTraceToFile(const char* filename) const;
    
    // Comparison
    static float computeSimilarity(const TraceFingerprint& a, const TraceFingerprint& b);
    
private:
    TraceBuffer& buffer_;
    HashState hasher_a_;
    HashState hasher_b_;
    uint64_t events_processed_;
    
    void processEvent(const TraceEvent& event);
    uint64_t hashValue(uint64_t val) const;
};

// C API for MASM interop
extern "C" {
    // Called from MASM interpreter
    void TraceCollector_Enable();
    void TraceCollector_Disable();
    void TraceCollector_Reset();
    void TraceCollector_RecordOpcode(uint64_t pc, uint8_t opcode);
    void TraceCollector_RecordRegister(uint8_t reg_idx, uint64_t value, uint8_t is_write);
    
    // Accessors
    uint64_t TraceCollector_GetFingerprintA();
    uint64_t TraceCollector_GetFingerprintB();
    uint32_t TraceCollector_GetEventCount();
}

// Pattern matching for bug classification
struct TracePattern {
    const char* name;
    const char* description;
    uint64_t signature_hash;  // Expected hash for this pattern
    uint8_t severity;         // 0=info, 1=warning, 2=error, 3=critical
};

// Known patterns (will be populated as we discover them)
extern const TracePattern kKnownPatterns[];
extern const size_t kKnownPatternCount;

} // namespace Script
} // namespace RawrXD
