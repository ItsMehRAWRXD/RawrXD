// RawrXD-Script Bug Pattern Database
// Maps trace fingerprints to known bug classifications

#ifndef BUG_PATTERN_DB_HPP
#define BUG_PATTERN_DB_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace RawrXD {
namespace Script {

// Bug severity levels
enum class BugSeverity {
    INFO,       // Informational, not a bug
    LOW,        // Minor issue, cosmetic
    MEDIUM,     // Functional issue, workaround exists
    HIGH,       // Serious bug, affects correctness
    CRITICAL    // Crash or data corruption
};

// Bug category classification
enum class BugCategory {
    NONE,
    ARITHMETIC_OVERFLOW,    // Integer/float overflow in operations
    DIVISION_BY_ZERO,       // Division or modulo by zero
    NULL_POINTER,          // Dereference of null/undefined
    TYPE_MISMATCH,         // Operation on incompatible types
    REGISTER_CORRUPTION,   // Register value unexpectedly changed
    STACK_OVERFLOW,        // Call stack exceeded limits
    MEMORY_LEAK,           // Unfreed allocations
    UNINITIALIZED_READ,    // Reading uninitialized memory
    BOUNDS_VIOLATION,      // Array/string out of bounds
    CONTROL_FLOW_ERROR,    // Wrong jump/branch taken
    INFINITE_LOOP,         // Execution exceeded step limit
    NATIVE_CALL_FAILED,    // External function call failed
    BYTECODE_INVALID,      // Corrupted or invalid bytecode
    TRACE_MISMATCH         // Execution trace differs from expected
};

// Single bug pattern entry
struct BugPattern {
    std::string id;                    // Unique pattern ID (e.g., "BUG_ARITH_001")
    BugCategory category;              // Classification category
    BugSeverity severity;              // Severity level
    std::string description;           // Human-readable description
    std::string fingerprint_prefix;    // Expected fingerprint prefix (hex)
    float similarity_threshold;        // Minimum similarity to match (0.0-1.0)
    std::vector<std::string> symptoms; // Observable symptoms
    std::string suggested_fix;         // Recommended fix approach
    bool is_regression;                // True if this is a known regression
};

// Pattern database
class BugPatternDatabase {
public:
    BugPatternDatabase();
    
    // Load built-in patterns
    void initializeBuiltinPatterns();
    
    // Match a fingerprint against known patterns
    // Returns the best matching pattern, or nullptr if no match above threshold
    const BugPattern* matchPattern(const std::string& fingerprint, float* similarity = nullptr) const;
    
    // Add a new pattern (for learning mode)
    void addPattern(const BugPattern& pattern);
    
    // Get all patterns in a category
    std::vector<const BugPattern*> getPatternsByCategory(BugCategory category) const;
    
    // Get severity string
    static const char* severityToString(BugSeverity severity);
    static const char* categoryToString(BugCategory category);
    
    // Compute similarity between two fingerprints
    static float computeFingerprintSimilarity(const std::string& fp1, const std::string& fp2);
    
private:
    std::vector<BugPattern> patterns_;
    std::unordered_map<std::string, size_t> pattern_index_; // fingerprint_prefix -> pattern index
    
    // Parse fingerprint string to hash components
    static void parseFingerprint(const std::string& fp, uint64_t& hash_a, uint64_t& hash_b);
};

// Global pattern database instance
BugPatternDatabase& getBugPatternDatabase();

// Built-in pattern definitions
namespace BuiltinPatterns {
    // Arithmetic operation errors
    extern const BugPattern ARITH_OVERFLOW_ADD;
    extern const BugPattern ARITH_OVERFLOW_MUL;
    extern const BugPattern DIV_BY_ZERO;
    extern const BugPattern MOD_BY_ZERO;
    
    // Type errors
    extern const BugPattern NULL_ARITHMETIC;
    extern const BugPattern UNDEFINED_PROP_ACCESS;
    extern const BugPattern TYPE_MISMATCH_COMPARISON;
    
    // Register/VM errors
    extern const BugPattern REGISTER_CORRUPTION_R8;
    extern const BugPattern REGISTER_CORRUPTION_R14;
    extern const BugPattern STACK_FRAME_MISALIGN;
    
    // Control flow errors
    extern const BugPattern INFINITE_LOOP_DETECTED;
    extern const BugPattern JUMP_OUT_OF_BOUNDS;
    extern const BugPattern INVALID_OPCODE;
    
    // Memory errors
    extern const BugPattern BUFFER_OVERFLOW_TRACE;
    extern const BugPattern CONSTANT_POOL_VIOLATION;
    
    // Known regressions from test history
    extern const BugPattern REGRESSION_ARITHMETIC_2024_01;
    extern const BugPattern REGRESSION_JUMP_OFFSET_2024_02;
    extern const BugPattern REGRESSION_NAN_BOXING_2024_03;
}

} // namespace Script
} // namespace RawrXD

#endif // BUG_PATTERN_DB_HPP
