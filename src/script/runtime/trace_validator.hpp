// RawrXD-Script Execution Trace Validator
// Records and validates per-instruction execution traces
// Connects MASM execution back to C++ test harness

#pragma once

#include "../bytecode/bytecode_contract.hpp"
#include <cstdint>
#include <vector>
#include <string>
#include <functional>

namespace RawrXD {
namespace Script {

// ============================================================================
// EXECUTION TRACE ENTRY
// ============================================================================
// Records a single instruction execution with inputs and outputs

struct TraceEntry {
    uint32_t pc;              // Program counter (instruction index)
    uint8_t opcode;           // Opcode executed
    uint64_t rawInstruction;  // Raw 4-byte instruction (packed)
    
    // Register state before execution
    uint64_t regBefore[16];   // v0-v15 values before
    
    // Register state after execution
    uint64_t regAfter[16];    // v0-v15 values after
    
    // Memory/heap effects (for object/array operations)
    uint64_t arenaBumpBefore;
    uint64_t arenaBumpAfter;
    
    // IC state (for property operations)
    uint32_t icSlotIndex;
    uint8_t icStateBefore;
    uint8_t icStateAfter;
    
    // Timing (optional, for performance analysis)
    uint64_t cycleCount;
    
    // Flags
    bool exceptionOccurred;
    bool icHit;
    bool icMiss;
};

// ============================================================================
// EXPECTED RESULT
// ============================================================================
// Defines expected behavior for validation

struct ExpectedResult {
    uint8_t opcode;
    
    // Expected output register value
    uint64_t expectedOutput;
    
    // Validation mode
    enum class Mode {
        kExactMatch,      // Value must match exactly
        kTypeMatch,       // Type must match (NaN-boxing tag)
        kRangeMatch,      // Value within range
        kPredicateMatch,  // Custom predicate
        kAny              // Any value acceptable
    } mode;
    
    // For range matching
    uint64_t minValue;
    uint64_t maxValue;
    
    // For predicate matching
    std::function<bool(uint64_t actual)> predicate;
    
    // Human-readable description
    const char* description;
};

// ============================================================================
// TRACE VALIDATOR
// ============================================================================
// Records execution traces and validates against expectations

class TraceValidator {
public:
    TraceValidator();
    ~TraceValidator();
    
    // Recording interface (called from MASM via callback)
    void BeginTrace(const char* testName);
    void RecordInstruction(const TraceEntry& entry);
    void EndTrace();
    
    // Validation interface
    void ExpectInstruction(uint32_t pc, const ExpectedResult& expected);
    void ExpectRegisterValue(uint8_t reg, uint64_t expected);
    void ExpectICState(uint32_t slot, uint8_t expectedState);
    
    // Execution
    bool Validate();
    
    // Results
    struct ValidationResult {
        bool passed;
        size_t totalInstructions;
        size_t checkedInstructions;
        size_t passedChecks;
        size_t failedChecks;
        std::vector<std::string> failures;
        
        void Print() const;
    };
    
    ValidationResult GetResult() const { return result_; }
    
    // Export/import
    void ExportTrace(const char* filename) const;
    bool ImportTrace(const char* filename);
    
    // Comparison
    bool CompareTraces(const TraceValidator& other) const;
    
    // Coverage
    size_t GetOpcodeCoverage(uint8_t opcode) const;
    void ResetCoverage();
    
private:
    std::vector<TraceEntry> trace_;
    std::vector<ExpectedResult> expectations_;
    ValidationResult result_;
    std::string currentTest_;
    
    // Opcode execution counts (for coverage)
    size_t opcodeCounts_[256];
    
    bool ValidateEntry(const TraceEntry& entry, const ExpectedResult& expected);
    bool ValuesMatch(uint64_t actual, const ExpectedResult& expected);
};

// ============================================================================
// MASM CALLBACK INTERFACE
// ============================================================================
// These functions are called from MASM to record execution

extern "C" {
    // Called at start of execution
    void Trace_Begin(const char* testName);
    
    // Called before each instruction
    void Trace_BeforeInstruction(
        uint32_t pc,
        uint8_t opcode,
        uint64_t rawInstr,
        const uint64_t* registers,
        uint64_t arenaBump
    );
    
    // Called after each instruction
    void Trace_AfterInstruction(
        const uint64_t* registers,
        uint64_t arenaBump,
        uint32_t icSlot,
        uint8_t icState
    );
    
    // Called at end of execution
    void Trace_End(uint64_t finalResult);
    
    // Called on exception
    void Trace_Exception(uint32_t pc, const char* message);
    
    // Get current trace validator instance
    TraceValidator* Trace_GetValidator();
}

// ============================================================================
// TRACE ASSERTIONS (for test harness)
// ============================================================================

#define TRACE_EXPECT_OPCODE(op) \
    validator.ExpectInstruction(__LINE__, {static_cast<uint8_t>(op), 0, ExpectedResult::Mode::kAny, 0, 0, nullptr, #op})

#define TRACE_EXPECT_VALUE(reg, val) \
    validator.ExpectRegisterValue(reg, val)

#define TRACE_EXPECT_IC_HIT(slot) \
    validator.ExpectICState(slot, 1) // IC_STATE_MONOMORPHIC

#define TRACE_ASSERT_PASS() \
    do { \
        auto result = validator.Validate(); \
        if (!result.passed) { \
            result.Print(); \
            return false; \
        } \
    } while(0)

} // namespace Script
} // namespace RawrXD
