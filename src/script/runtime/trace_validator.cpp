// RawrXD-Script Execution Trace Validator Implementation

#include "trace_validator.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <json/json.h>

namespace RawrXD {
namespace Script {

// Global validator instance (singleton for MASM callbacks)
static TraceValidator* g_validator = nullptr;

TraceValidator::TraceValidator() {
    std::memset(opcodeCounts_, 0, sizeof(opcodeCounts_));
}

TraceValidator::~TraceValidator() = default;

void TraceValidator::BeginTrace(const char* testName) {
    currentTest_ = testName ? testName : "unknown";
    trace_.clear();
    expectations_.clear();
    result_ = ValidationResult{};
    std::memset(opcodeCounts_, 0, sizeof(opcodeCounts_));
    
    printf("[Trace] Beginning: %s\n", currentTest_.c_str());
}

void TraceValidator::RecordInstruction(const TraceEntry& entry) {
    trace_.push_back(entry);
    opcodeCounts_[entry.opcode]++;
    
    // Print verbose trace (can be disabled in release)
    #ifdef TRACE_VERBOSE
    printf("[Trace] PC=%04u OP=%02X ", entry.pc, entry.opcode);
    
    // Print register changes
    for (int i = 0; i < 4; i++) {
        if (entry.regBefore[i] != entry.regAfter[i]) {
            printf("v%d:%llx->%llx ", i, 
                   (unsigned long long)entry.regBefore[i],
                   (unsigned long long)entry.regAfter[i]);
        }
    }
    
    if (entry.icHit) printf("[IC_HIT] ");
    if (entry.icMiss) printf("[IC_MISS] ");
    if (entry.exceptionOccurred) printf("[EXCEPTION] ");
    
    printf("\n");
    #endif
}

void TraceValidator::EndTrace() {
    printf("[Trace] Completed: %zu instructions\n", trace_.size());
    
    // Print coverage summary
    printf("[Trace] Opcode coverage:\n");
    size_t uniqueOpcodes = 0;
    for (int i = 0; i < 256; i++) {
        if (opcodeCounts_[i] > 0) {
            printf("  0x%02X: %zu executions\n", i, opcodeCounts_[i]);
            uniqueOpcodes++;
        }
    }
    printf("[Trace] Unique opcodes executed: %zu/256\n", uniqueOpcodes);
}

void TraceValidator::ExpectInstruction(uint32_t pc, const ExpectedResult& expected) {
    expectations_.push_back(expected);
}

void TraceValidator::ExpectRegisterValue(uint8_t reg, uint64_t expected) {
    ExpectedResult er;
    er.opcode = 0xFF; // Any opcode
    er.expectedOutput = expected;
    er.mode = ExpectedResult::Mode::kExactMatch;
    er.description = "register value check";
    expectations_.push_back(er);
}

void TraceValidator::ExpectICState(uint32_t slot, uint8_t expectedState) {
    // TODO: Implement IC state validation
}

bool TraceValidator::Validate() {
    result_.totalInstructions = trace_.size();
    result_.checkedInstructions = 0;
    result_.passedChecks = 0;
    result_.failedChecks = 0;
    
    // Validate each trace entry against expectations
    for (size_t i = 0; i < trace_.size() && i < expectations_.size(); i++) {
        result_.checkedInstructions++;
        
        if (ValidateEntry(trace_[i], expectations_[i])) {
            result_.passedChecks++;
        } else {
            result_.failedChecks++;
            char failure[256];
            snprintf(failure, sizeof(failure),
                "PC=%04zu: Expected %s, got opcode 0x%02X",
                i, expectations_[i].description, trace_[i].opcode);
            result_.failures.push_back(failure);
        }
    }
    
    result_.passed = (result_.failedChecks == 0);
    return result_.passed;
}

bool TraceValidator::ValidateEntry(const TraceEntry& entry, const ExpectedResult& expected) {
    // Check opcode match
    if (expected.opcode != 0xFF && entry.opcode != expected.opcode) {
        return false;
    }
    
    // Check value based on mode
    return ValuesMatch(entry.regAfter[0], expected); // Check accumulator
}

bool TraceValidator::ValuesMatch(uint64_t actual, const ExpectedResult& expected) {
    switch (expected.mode) {
        case ExpectedResult::Mode::kExactMatch:
            return actual == expected.expectedOutput;
            
        case ExpectedResult::Mode::kTypeMatch:
            // Compare NaN-boxing tags
            return (actual & 0x7FF8000000000000ULL) == 
                   (expected.expectedOutput & 0x7FF8000000000000ULL);
            
        case ExpectedResult::Mode::kRangeMatch:
            return actual >= expected.minValue && actual <= expected.maxValue;
            
        case ExpectedResult::Mode::kPredicateMatch:
            return expected.predicate(actual);
            
        case ExpectedResult::Mode::kAny:
            return true;
            
        default:
            return false;
    }
}

void TraceValidator::ValidationResult::Print() const {
    printf("\n=== Trace Validation Result ===\n");
    printf("Passed: %s\n", passed ? "YES" : "NO");
    printf("Total Instructions: %zu\n", totalInstructions);
    printf("Checked: %zu\n", checkedInstructions);
    printf("Passed: %zu\n", passedChecks);
    printf("Failed: %zu\n", failedChecks);
    
    if (!failures.empty()) {
        printf("\nFailures:\n");
        for (const auto& f : failures) {
            printf("  - %s\n", f.c_str());
        }
    }
    printf("===============================\n\n");
}

void TraceValidator::ExportTrace(const char* filename) const {
    std::ofstream file(filename);
    if (!file) return;
    
    file << "{\n";
    file << "  \"test\": \"" << currentTest_ << "\",\n";
    file << "  \"instructions\": [\n";
    
    for (size_t i = 0; i < trace_.size(); i++) {
        const auto& e = trace_[i];
        file << "    {\n";
        file << "      \"pc\": " << e.pc << ",\n";
        file << "      \"opcode\": " << (int)e.opcode << ",\n";
        file << "      \"raw\": " << e.rawInstruction << ",\n";
        file << "      \"ic_hit\": " << (e.icHit ? "true" : "false") << ",\n";
        file << "      \"ic_miss\": " << (e.icMiss ? "true" : "false") << "\n";
        file << "    }";
        if (i < trace_.size() - 1) file << ",";
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
}

bool TraceValidator::ImportTrace(const char* filename) {
    // TODO: Implement JSON import
    return false;
}

bool TraceValidator::CompareTraces(const TraceValidator& other) const {
    if (trace_.size() != other.trace_.size()) {
        return false;
    }
    
    for (size_t i = 0; i < trace_.size(); i++) {
        if (trace_[i].opcode != other.trace_[i].opcode) {
            return false;
        }
        if (trace_[i].regAfter[0] != other.trace_[i].regAfter[0]) {
            return false;
        }
    }
    
    return true;
}

size_t TraceValidator::GetOpcodeCoverage(uint8_t opcode) const {
    return opcodeCounts_[opcode];
}

void TraceValidator::ResetCoverage() {
    std::memset(opcodeCounts_, 0, sizeof(opcodeCounts_));
}

// ============================================================================
// MASM CALLBACK IMPLEMENTATION
// ============================================================================

extern "C" {

void Trace_Begin(const char* testName) {
    if (!g_validator) {
        g_validator = new TraceValidator();
    }
    g_validator->BeginTrace(testName);
}

void Trace_BeforeInstruction(
    uint32_t pc,
    uint8_t opcode,
    uint64_t rawInstr,
    const uint64_t* registers,
    uint64_t arenaBump
) {
    if (!g_validator) return;
    
    TraceEntry entry;
    entry.pc = pc;
    entry.opcode = opcode;
    entry.rawInstruction = rawInstr;
    std::memcpy(entry.regBefore, registers, sizeof(entry.regBefore));
    entry.arenaBumpBefore = arenaBump;
    entry.exceptionOccurred = false;
    entry.icHit = false;
    entry.icMiss = false;
    
    // Store temporarily - will be completed by Trace_AfterInstruction
    // For now, just record the before state
}

void Trace_AfterInstruction(
    const uint64_t* registers,
    uint64_t arenaBump,
    uint32_t icSlot,
    uint8_t icState
) {
    if (!g_validator) return;
    
    // Complete the trace entry
    // This is simplified - in production, we'd match before/after
}

void Trace_End(uint64_t finalResult) {
    if (!g_validator) return;
    g_validator->EndTrace();
}

void Trace_Exception(uint32_t pc, const char* message) {
    if (!g_validator) return;
    printf("[Trace] Exception at PC=%u: %s\n", pc, message);
}

TraceValidator* Trace_GetValidator() {
    return g_validator;
}

} // extern "C"

} // namespace Script
} // namespace RawrXD
