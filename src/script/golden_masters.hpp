// RawrXD-Script Golden Master Fingerprints
// Known-good execution traces for regression detection

#ifndef GOLDEN_MASTERS_HPP
#define GOLDEN_MASTERS_HPP

#include <cstdint>
#include <string>

namespace RawrXD {
namespace Script {

// Golden Master fingerprint entry
struct GoldenMaster {
    const char* name;           // Test name (e.g., "add_basic")
    const char* description;      // Human-readable description
    const char* source_code;      // JavaScript source
    const char* fingerprint;      // Expected trace fingerprint (hex)
    uint64_t expected_result;     // Expected execution result
    uint8_t expected_opcode;      // Primary opcode being tested
};

// Pre-defined Golden Masters for ALU operations
namespace GoldenMasters {
    // Basic arithmetic - ADD (verified working)
    constexpr GoldenMaster ADD_BASIC = {
        "add_basic",
        "Basic addition: 10 + 20 = 30",
        "10 + 20",
        "DCA96B04CCB60B27-35EC38805B476187",  // Fingerprint from trace
        30,
        0x20  // OP_ADD
    };
    
    // Subtraction (currently buggy - does addition instead)
    constexpr GoldenMaster SUB_BASIC = {
        "sub_basic",
        "Basic subtraction: 100 - 45 = 55",
        "100 - 45",
        "",  // To be determined when fixed
        55,
        0x21  // OP_SUB
    };
    
    // Multiplication (currently buggy - does addition instead)
    constexpr GoldenMaster MUL_BASIC = {
        "mul_basic",
        "Basic multiplication: 6 * 7 = 42",
        "6 * 7",
        "",  // To be determined when fixed
        42,
        0x22  // OP_MUL
    };
    
    // Division (currently buggy - does addition instead)
    constexpr GoldenMaster DIV_BASIC = {
        "div_basic",
        "Basic division: 100 / 4 = 25",
        "100 / 4",
        "",  // To be determined when fixed
        25,
        0x23  // OP_DIV
    };
}

// Bug pattern for "ALU dispatch failure - always executes ADD"
// This occurs when opcode dispatch falls through to ADD handler
namespace BugPatterns {
    constexpr const char* ALU_DISPATCH_FAILURE = "ALU_DISPATCH_FAILURE";
    constexpr const char* DESCRIPTION = 
        "Interpreter always executes ADD regardless of opcode. "
        "Dispatch table may have fall-through or comparison logic error.";
}

} // namespace Script
} // namespace RawrXD

#endif // GOLDEN_MASTERS_HPP
