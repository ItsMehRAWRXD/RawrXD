// RawrXD-Script Trace Collector MASM Interface
// C++ wrapper for MASM trace collector implementation
// Provides zero-overhead integration between C++ and assembly trace collection

#pragma once

#include <cstdint>
#include <cstring>
#include <utility>
#include <cstdio>

namespace RawrXD {
namespace Script {

// Forward declaration - matches the MASM structure layout
struct TraceCollectorState {
    uint64_t fingerprint_low;      // Lower 64 bits of 128-bit fingerprint
    uint64_t fingerprint_high;     // Upper 64 bits of 128-bit fingerprint
    uint32_t event_count;          // Number of events recorded
    uint8_t  is_recording;         // Boolean: is recording active
    uint8_t  reserved[3];          // Padding to 24 bytes
    // Event buffer follows (1024 * 8 bytes)
    uint8_t  event_buffer[1024 * 8]; // Circular buffer for events
    uint32_t buffer_head;          // Write position
    uint32_t buffer_tail;          // Read position
    uint32_t buffer_count;         // Current event count
    uint32_t reserved2;            // Padding
    uint32_t pattern_match_id;     // Matched pattern ID (0 = none)
    uint32_t match_confidence;     // Confidence score (0-100)
};

// 128-bit execution fingerprint
struct ExecutionFingerprint {
    uint64_t low;
    uint64_t high;
    
    bool operator==(const ExecutionFingerprint& other) const {
        return low == other.low && high == other.high;
    }
    
    bool operator!=(const ExecutionFingerprint& other) const {
        return !(*this == other);
    }
    
    // Convert to string for display/logging
    void ToString(char* buffer, size_t bufferSize) const {
        if (bufferSize >= 33) {
            snprintf(buffer, bufferSize, "%016llX%016llX", high, low);
        }
    }
};

// External MASM functions (implemented in trace_collector_masm.asm)
extern "C" {
    // Record an opcode execution event
    // Parameters:
    //   opcode - the opcode being executed
    //   pc - program counter
    void TraceCollector_RecordOpcode(uint16_t opcode, uint64_t pc);
    
    // Record a register access event
    // Parameters:
    //   reg_index - register index
    //   value - register value
    void TraceCollector_RecordRegister(uint8_t reg_index, uint64_t value);
    
    // Get the current execution fingerprint
    // Parameter: buffer - pointer to 16-byte buffer (uint64_t[2])
    void TraceCollector_GetFingerprint(uint64_t* buffer);
    
    // Clear the trace buffer
    void TraceCollector_Clear();
    
    // Get number of recorded events
    // Returns: event count
    uint64_t TraceCollector_GetEventCount();
    
    // Get pointer to trace buffer
    // Returns: pointer to trace buffer
    uint64_t* TraceCollector_GetBufferPtr();
}

// C++ wrapper class for type-safe trace collection
class MASMTraceCollector {
public:
    // Clear the trace collector
    static void Reset() {
        TraceCollector_Clear();
    }
    
    // Start recording (clear buffer)
    static void Start() {
        TraceCollector_Clear();
    }
    
    // Stop recording (no-op for now)
    static void Stop() {
        // No-op
    }
    
    // Check if recording (always true for now)
    static bool IsRecording() {
        return true;
    }
    
    // Get current fingerprint
    static ExecutionFingerprint GetFingerprint() {
        ExecutionFingerprint fp;
        TraceCollector_GetFingerprint(reinterpret_cast<uint64_t*>(&fp));
        return fp;
    }
    
    // Get event count
    static uint32_t GetEventCount() {
        return static_cast<uint32_t>(TraceCollector_GetEventCount());
    }
    
    // Record an opcode execution event
    static void RecordOpcode(uint8_t opcode, uint8_t reg0 = 0, uint8_t reg1 = 0) {
        // Pack event: [opcode:8][reg0:8][reg1:8][reserved:40]
        uint64_t pc = (static_cast<uint64_t>(reg1) << 16) |
                      (static_cast<uint64_t>(reg0) << 8) |
                      opcode;
        TraceCollector_RecordOpcode(opcode, pc);
    }
    
    // Record a register state event
    static void RecordRegister(uint8_t regIndex, uint64_t value) {
        TraceCollector_RecordRegister(regIndex, value);
    }
    
    // Record a memory access event
    static void RecordMemoryAccess(uint64_t address, uint32_t size, bool isWrite) {
        // Pack event: [isWrite:1][size:7][address:56]
        uint64_t value = (static_cast<uint64_t>(isWrite) << 63) |
                        (static_cast<uint64_t>(size) << 56) |
                        (address & 0x00FFFFFFFFFFFFFF);
        TraceCollector_RecordRegister(0xFF, value);  // Use register 0xFF for memory events
    }
    
    // Record a branch event
    static void RecordBranch(uint64_t fromPC, uint64_t toPC, bool isTaken) {
        // Pack event: [isTaken:1][fromPC:31][toPC:32]
        uint64_t value = (static_cast<uint64_t>(isTaken) << 63) |
                        ((fromPC & 0x7FFFFFFF) << 32) |
                        (toPC & 0xFFFFFFFF);
        TraceCollector_RecordRegister(0xFE, value);  // Use register 0xFE for branch events
    }
};

// Bug pattern matching (C++ side - pattern database)
enum class BugPattern : uint32_t {
    None = 0,
    // Memory corruption patterns
    HeapUseAfterFree = 1,
    HeapDoubleFree = 2,
    StackBufferOverflow = 3,
    HeapBufferOverflow = 4,
    
    // Logic errors
    InfiniteLoop = 10,
    UninitializedRead = 11,
    IntegerOverflow = 12,
    DivisionByZero = 13,
    
    // Control flow
    ReturnOrientedProgramming = 20,
    JumpOrientedProgramming = 21,
    
    // Concurrency
    RaceCondition = 30,
    Deadlock = 31,
    
    // VM-specific
    OpcodeSequenceAnomaly = 40,
    RegisterStateAnomaly = 41,
    ArenaExhaustion = 42,
    ICChainExhaustion = 43,
    
    // Unknown/uncategorized
    UnknownAnomaly = 0xFFFFFFFF
};

// Pattern matcher for bug classification
class BugPatternMatcher {
public:
    // Match a fingerprint against known bug patterns
    // Returns: pair of (pattern_id, confidence_score)
    static std::pair<BugPattern, uint32_t> MatchPattern(
        const ExecutionFingerprint& fingerprint);
    
    // Add a new pattern to the database
    static void RegisterPattern(
        BugPattern pattern,
        const ExecutionFingerprint& fingerprint,
        uint32_t confidenceThreshold = 90);
    
    // Get pattern description
    static const char* GetPatternDescription(BugPattern pattern);
};

} // namespace Script
} // namespace RawrXD
