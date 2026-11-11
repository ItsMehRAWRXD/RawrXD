// RawrXD-Script MASM Interface
// C++ wrapper for calling MASM interpreter

#pragma once

#include <cstdint>
#include <string>

namespace RawrXD {
namespace Script {
namespace MASM {

// NaN-boxed value type (matches MASM)
using JsValue = uint64_t;

// Constants
constexpr JsValue JS_NULL = 0x7FF3000000000000ULL;
constexpr JsValue JS_UNDEFINED = 0x7FF3000000000001ULL;
constexpr JsValue JS_TRUE = 0x7FF2000000000001ULL;
constexpr JsValue JS_FALSE = 0x7FF2000000000000ULL;

// Tag extraction
constexpr uint8_t GetTag(JsValue val) {
    return static_cast<uint8_t>((val >> 48) & 0xF);
}

constexpr bool IsInt32(JsValue val) {
    return (val & 0x7FF9000000000000ULL) == 0x7FF9000000000000ULL;
}

constexpr bool IsBoolean(JsValue val) {
    return (val & 0x7FF2000000000000ULL) == 0x7FF2000000000000ULL;
}

constexpr bool IsString(JsValue val) {
    return (val & 0x7FF4000000000000ULL) == 0x7FF4000000000000ULL;
}

constexpr bool IsObject(JsValue val) {
    return (val & 0x7FF5000000000000ULL) == 0x7FF5000000000000ULL;
}

constexpr bool IsPointer(JsValue val) {
    return (val & 0x7FF8000000000000ULL) == 0x7FF8000000000000ULL && GetTag(val) >= 4;
}

// Boxing functions
constexpr JsValue BoxInt32(int32_t val) {
    return (static_cast<uint64_t>(val & 0x00007FFFFFFFFFFFULL)) | 0x7FF9000000000000ULL;
}

constexpr JsValue BoxBool(bool val) {
    return val ? JS_TRUE : JS_FALSE;
}

constexpr JsValue BoxDouble(double val) {
    // For now, just store as-is (not NaN-boxed)
    union { double d; uint64_t u; } conv;
    conv.d = val;
    return conv.u;
}

// Unboxing functions
constexpr int32_t UnboxInt32(JsValue val) {
    return static_cast<int32_t>(val & 0x00000000FFFFFFFFULL);
}

constexpr bool UnboxBool(JsValue val) {
    return (val & 1) != 0;
}

constexpr double UnboxDouble(JsValue val) {
    union { uint64_t u; double d; } conv;
    conv.u = val;
    return conv.d;
}

// Pointer extraction
constexpr void* UnboxPointer(JsValue val) {
    return reinterpret_cast<void*>(val & 0x0000FFFFFFFFFFFFULL);
}

// ============================================================================
// VM State
// ============================================================================

struct VMState {
    uint64_t pc;           // Program counter
    uint64_t codeBase;     // Code section base
    uint64_t constPool;    // Constant pool base
    uint64_t globalObj;    // Global object
    uint64_t arenaBase;    // Arena base
    uint64_t arenaBump;    // Arena bump pointer
    uint64_t icTable;      // Inline cache table
    uint64_t v0, v1, v2, v3; // Virtual registers
    uint64_t frame;        // Frame pointer
};

// ============================================================================
// Arena Management
// ============================================================================

struct SovereignArena {
    void* base;
    size_t size;
    size_t committed;
    size_t used;
    uint32_t extensionId;
    uint32_t flags;
    SovereignArena* next;
};

// Arena flags
constexpr uint32_t ARENA_FLAG_ACTIVE = 0x0001;
constexpr uint32_t ARENA_FLAG_FROZEN = 0x0002;
constexpr uint32_t ARENA_FLAG_ASYNC = 0x0004;

// ============================================================================
// External Functions (from MASM)
// ============================================================================

extern "C" {
    // Core interpreter
    JsValue JsInterpreter_Run(
        const uint8_t* bytecode,
        size_t bytecodeSize,
        const uint8_t* constPool,
        JsValue globalObj,
        SovereignArena* arena,
        void* icTable
    );
    
    // Arena management
    SovereignArena* JsInterpreter_CreateArena(size_t initialSize);
    void JsInterpreter_DestroyArena(SovereignArena* arena);
    void* JsInterpreter_ArenaAlloc(SovereignArena* arena, size_t size);
    
    // Value operations
    int JsValue_IsTruthy(JsValue val);
    int JsValue_ToString(JsValue val, char* buffer, size_t bufferSize);
    
    // String operations
    JsValue JsString_Concat(JsValue a, JsValue b, SovereignArena* arena);
    JsValue JsString_Length(JsValue str);
    
    // Object operations
    void* JsObject_Create(void* shape, SovereignArena* arena);
    JsValue JsObject_GetProperty(JsValue obj, JsValue propName, void* icSlot);
    int JsObject_SetProperty(JsValue obj, JsValue propName, JsValue value, void* icSlot);
    
    // Array operations
    void* JsArray_Create(size_t capacity, SovereignArena* arena);
    JsValue JsArray_Push(JsValue arr, JsValue val, SovereignArena* arena);
    
    // Math operations
    JsValue JsMath_Add(JsValue a, JsValue b, SovereignArena* arena);
    
    // Comparison
    JsValue JsCompare_AbstractEqual(JsValue a, JsValue b);
    JsValue JsCompare_StrictEqual(JsValue a, JsValue b);
}

// ============================================================================
// C++ Wrapper Classes
// ============================================================================

class Interpreter {
public:
    Interpreter();
    ~Interpreter();
    
    // Initialize with bytecode
    bool LoadBytecode(const uint8_t* data, size_t size);
    bool LoadBytecode(const std::vector<uint8_t>& data);
    
    // Execute
    JsValue Execute();
    JsValue Execute(JsValue thisObj, const std::vector<JsValue>& args);
    
    // Get/set global
    JsValue GetGlobal(const std::string& name);
    void SetGlobal(const std::string& name, JsValue val);
    
    // Arena access
    SovereignArena* GetArena() const { return arena_; }
    
    // State inspection
    VMState GetState() const;
    void SetState(const VMState& state);
    
private:
    std::vector<uint8_t> bytecode_;
    std::vector<uint8_t> constPool_;
    SovereignArena* arena_;
    void* icTable_;
    JsValue globalObj_;
    bool loaded_;
    std::map<std::string, JsValue> globalCache_;
};

class Value {
public:
    Value() : value_(JS_UNDEFINED) {}
    Value(JsValue v) : value_(v) {}
    Value(int32_t i) : value_(BoxInt32(i)) {}
    Value(bool b) : value_(BoxBool(b)) {}
    Value(double d) : value_(BoxDouble(d)) {}
    Value(nullptr_t) : value_(JS_NULL) {}
    
    // Type checks
    bool IsInt32() const { return MASM::IsInt32(value_); }
    bool IsBool() const { return MASM::IsBoolean(value_); }
    bool IsString() const { return MASM::IsString(value_); }
    bool IsObject() const { return MASM::IsObject(value_); }
    bool IsNull() const { return value_ == JS_NULL; }
    bool IsUndefined() const { return value_ == JS_UNDEFINED; }
    bool IsTruthy() const;
    
    // Unboxing
    int32_t AsInt32() const { return UnboxInt32(value_); }
    bool AsBool() const { return UnboxBool(value_); }
    double AsDouble() const { return UnboxDouble(value_); }
    std::string AsString() const;
    
    // Raw access
    JsValue Raw() const { return value_; }
    
    // Operators
    bool operator==(const Value& other) const { return value_ == other.value_; }
    bool operator!=(const Value& other) const { return value_ != other.value_; }
    
private:
    JsValue value_;
};

} // namespace MASM
} // namespace Script
} // namespace RawrXD
