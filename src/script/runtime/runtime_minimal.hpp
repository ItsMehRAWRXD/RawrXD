// RawrXD-Script Minimal Runtime API
// Absolute minimum surface for Phase 1 integration

#pragma once

#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace Script {

// Opaque handle to runtime instance
struct Runtime;
struct Interpreter;

// JsValue is NaN-boxed 64-bit value
struct JsValue {
    uint64_t raw;
    
    // Constructors
    static JsValue Undefined();
    static JsValue Null();
    static JsValue Bool(bool b);
    static JsValue Number(double d);
    static JsValue Int32(int32_t i);
    
    // Type checks
    bool IsUndefined() const;
    bool IsNull() const;
    bool IsBool() const;
    bool IsNumber() const;
    bool IsInt32() const;
    
    // Extractors
    bool GetBool() const;
    double GetNumber() const;
    int32_t GetInt32() const;
    
    // Equality
    bool operator==(const JsValue& other) const;
    bool operator!=(const JsValue& other) const;
};

// Minimal Runtime API - Phase 1
extern "C" {
    // Lifecycle
    Runtime* CreateRuntime();
    void DestroyRuntime(Runtime* rt);
    void ResetRuntime(Runtime* rt);
    
    // Execution
    // Returns true on success, false on exception
    // Output value stored in *result
    bool ExecuteBytecode(
        Runtime* rt,
        const uint8_t* bytecode,
        size_t bytecodeLen,
        JsValue* result
    );
    
    // Error handling
    const char* GetExceptionString(Runtime* rt);
    void ClearException(Runtime* rt);
    
    // Coverage (optional, enabled via RAWRXD_PROFILE_COVERAGE)
    void ResetCoverage();
    uint32_t GetOpcodeExecutionCount(uint8_t opcode);
}

} // namespace Script
} // namespace RawrXD
