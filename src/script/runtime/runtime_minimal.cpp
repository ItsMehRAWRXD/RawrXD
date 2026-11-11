// RawrXD-Script Minimal Runtime Implementation
// Absolute minimum for Phase 1 integration

#include "runtime_minimal.hpp"
#include <cstring>
#include <cmath>
#include <cstdint>

namespace RawrXD {
namespace Script {

// ============================================================================
// NaN-Boxing Constants
// ============================================================================

static const uint64_t kNaNMask = 0x7FF8000000000000ULL;
static const uint64_t kTagUndefined = 0x1;
static const uint64_t kTagNull = 0x2;
static const uint64_t kTagBool = 0x3;
static const uint64_t kTagInt32 = 0x4;
static const uint64_t kTagObject = 0x5;
static const uint64_t kTagString = 0x6;

// ============================================================================
// JsValue Implementation
// ============================================================================

JsValue JsValue::Undefined() {
    JsValue v;
    v.raw = kNaNMask | kTagUndefined;
    return v;
}

JsValue JsValue::Null() {
    JsValue v;
    v.raw = kNaNMask | kTagNull;
    return v;
}

JsValue JsValue::Bool(bool b) {
    JsValue v;
    v.raw = kNaNMask | kTagBool | (b ? 1ULL : 0ULL);
    return v;
}

JsValue JsValue::Number(double d) {
    JsValue v;
    // Check if it's a NaN-boxed value
    uint64_t bits;
    static_assert(sizeof(bits) == sizeof(d), "Size mismatch");
    std::memcpy(&bits, &d, sizeof(d));
    
    // If it's a quiet NaN, we need to ensure it's not one of our tags
    if ((bits & kNaNMask) == kNaNMask) {
        bits = kNaNMask; // Canonical quiet NaN
    }
    v.raw = bits;
    return v;
}

JsValue JsValue::Int32(int32_t i) {
    JsValue v;
    // Format: 0x7FF8000000000004 | (value & 0xFFFFFFFF)
    // Tag is in bits 32-35, value is in bits 0-31
    v.raw = kNaNMask | (kTagInt32 << 32) | (static_cast<uint64_t>(i) & 0xFFFFFFFFULL);
    return v;
}

bool JsValue::IsUndefined() const {
    return (raw & kNaNMask) == kNaNMask && (raw & 0xF) == kTagUndefined;
}

bool JsValue::IsNull() const {
    return (raw & kNaNMask) == kNaNMask && (raw & 0xF) == kTagNull;
}

bool JsValue::IsBool() const {
    return (raw & kNaNMask) == kNaNMask && (raw & 0xF) == kTagBool;
}

bool JsValue::IsNumber() const {
    // Not a NaN-boxed value (check if top 16 bits are not QNaN pattern)
    return (raw & 0x7FF8000000000000ULL) != 0x7FF8000000000000ULL;
}

bool JsValue::IsInt32() const {
    // Check if it's a NaN-boxed value with Int32 tag in bits 32-35
    // Format: 0x7FF8000000000004 | value
    return (raw & 0xFFFFFFFF00000000ULL) == (kNaNMask | (kTagInt32 << 32));
}

bool JsValue::GetBool() const {
    return (raw & 1) != 0;
}

double JsValue::GetNumber() const {
    double d;
    std::memcpy(&d, &raw, sizeof(d));
    return d;
}

int32_t JsValue::GetInt32() const {
    // Extract the lower 32 bits which contain the signed int32 value
    return static_cast<int32_t>(raw);
}

bool JsValue::operator==(const JsValue& other) const {
    return raw == other.raw;
}

bool JsValue::operator!=(const JsValue& other) const {
    return raw != other.raw;
}

// ============================================================================
// Runtime State
// ============================================================================

struct Runtime {
    // Arena for allocations
    uint8_t* arenaBase;
    uint8_t* arenaBump;
    size_t arenaSize;
    
    // Exception state
    char exceptionBuffer[1024];
    bool hasException;
    
    // Coverage tracking (optional)
    uint32_t opcodeCounts[256];
    bool coverageEnabled;
    
    Runtime() : arenaBase(nullptr), arenaBump(nullptr), arenaSize(0), 
                hasException(false), coverageEnabled(false) {
        std::memset(opcodeCounts, 0, sizeof(opcodeCounts));
        exceptionBuffer[0] = '\0';
    }
};

// ============================================================================
// Runtime API Implementation
// ============================================================================

extern "C" {

Runtime* CreateRuntime() {
    Runtime* rt = new Runtime();
    
    // Allocate initial arena (1MB)
    rt->arenaSize = 1024 * 1024;
    rt->arenaBase = new uint8_t[rt->arenaSize];
    rt->arenaBump = rt->arenaBase;
    
    return rt;
}

void DestroyRuntime(Runtime* rt) {
    if (rt) {
        delete[] rt->arenaBase;
        delete rt;
    }
}

void ResetRuntime(Runtime* rt) {
    if (!rt) return;
    
    // Reset arena
    rt->arenaBump = rt->arenaBase;
    
    // Clear exception
    rt->hasException = false;
    rt->exceptionBuffer[0] = '\0';
    
    // Reset coverage
    std::memset(rt->opcodeCounts, 0, sizeof(rt->opcodeCounts));
}

// External MASM interpreter function
// Defined in interpreter_full.asm
// Entry: rcx = bytecode ptr, rdx = bytecode size, r8 = constant pool, r9 = result ptr
// Exit:  rax = 1 (success) or 0 (failure)
extern "C" int JsInterpreter_Run(
    uint8_t* bytecode,
    size_t bytecodeLen,
    uint64_t* constants,
    uint64_t* result
);

// Wrapper to call MASM interpreter from C++
extern "C" bool ExecuteBytecode_MASM(
    Runtime* rt,
    const uint8_t* bytecode,
    size_t bytecodeLen,
    uint64_t* result
) {
    if (!rt || !bytecode || !result || bytecodeLen == 0) {
        return false;
    }
    
    // Call the actual MASM interpreter
    // Note: constants are embedded in bytecode, so pass nullptr for now
    int success = JsInterpreter_Run(
        const_cast<uint8_t*>(bytecode),
        bytecodeLen,
        nullptr,  // constants (would need to extract from bytecode module)
        result
    );
    
    return success != 0;
}

bool ExecuteBytecode(
    Runtime* rt,
    const uint8_t* bytecode,
    size_t bytecodeLen,
    JsValue* result
) {
    if (!rt || !bytecode || !result) {
        return false;
    }
    
    // Clear previous exception
    rt->hasException = false;
    rt->exceptionBuffer[0] = '\0';
    
    // Call MASM interpreter
    uint64_t rawResult = 0;
    bool success = ExecuteBytecode_MASM(rt, bytecode, bytecodeLen, &rawResult);
    
    if (success) {
        result->raw = rawResult;
    } else {
        // Exception occurred
        rt->hasException = true;
        std::strncpy(rt->exceptionBuffer, "Execution failed", sizeof(rt->exceptionBuffer) - 1);
        result->raw = JsValue::Undefined().raw;
    }
    
    return success;
}

const char* GetExceptionString(Runtime* rt) {
    if (!rt || !rt->hasException) {
        return nullptr;
    }
    return rt->exceptionBuffer;
}

void ClearException(Runtime* rt) {
    if (rt) {
        rt->hasException = false;
        rt->exceptionBuffer[0] = '\0';
    }
}

void ResetCoverage() {
    // Global coverage reset - would iterate all runtimes in full impl
}

uint32_t GetOpcodeExecutionCount(uint8_t opcode) {
    // Would query runtime in full impl
    return 0;
}

} // extern "C"

} // namespace Script
} // namespace RawrXD
