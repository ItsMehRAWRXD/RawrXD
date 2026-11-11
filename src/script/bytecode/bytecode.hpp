// RawrXD-Script Bytecode Format
// Phase 1: Bytecode Spec + C++ Parser
// Binary format specification matching masm_nodejs_vision.md

#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace RawrXD {
namespace Script {
namespace Bytecode {

// ============================================================================
// Binary Format Header
// ============================================================================

// Magic number: 'RAWR' in little-endian
constexpr uint32_t kBytecodeMagic = 0x52415752;
constexpr uint16_t kBytecodeVersion = 1;

// Bytecode file header (matches spec in masm_nodejs_vision.md)
struct BytecodeHeader {
    uint32_t magic;              // 'RAWR' (0x52415752)
    uint16_t version;          // 1
    uint16_t flags;            // See BC_FLAG_* below
    uint32_t code_offset;      // Offset to code section from header start
    uint32_t code_size;        // Size of code section (bytes)
    uint32_t const_pool_offset;// Offset to constant pool
    uint32_t const_pool_count; // Number of constants
    uint32_t string_table_offset;      // Offset to string table
    uint32_t string_table_size;// Size of string table (bytes)
    uint32_t ic_slot_count;    // Number of inline cache slots
    uint32_t line_info_offset; // Offset to line number table (debug)
    
    // Padding to 64-byte alignment
    uint32_t reserved[4];
};

// Header flags
constexpr uint16_t BC_FLAG_STRICT_MODE    = 0x0001;
constexpr uint16_t BC_FLAG_HAS_DEBUG_INFO = 0x0002;
constexpr uint16_t BC_FLAG_ASYNC_FUNCTION = 0x0004;

// ============================================================================
// Opcodes (256 total, matching spec)
// ============================================================================

enum class Opcode : uint8_t {
    // Constants (0x00-0x0F)
    OP_LOAD_CONST = 0x00,      // r_dest = const_pool[idx]
    OP_LOAD_INT,                 // r_dest = immediate_int
    OP_LOAD_DOUBLE,              // r_dest = immediate_double
    OP_LOAD_STRING,              // r_dest = string_table[idx]
    OP_LOAD_NULL,                // r_dest = null
    OP_LOAD_UNDEFINED,           // r_dest = undefined
    OP_LOAD_TRUE,                // r_dest = true
    OP_LOAD_FALSE,               // r_dest = false
    OP_LOAD_ZERO = 0x08,         // r_dest = 0 (optimization)
    OP_LOAD_ONE,                 // r_dest = 1 (optimization)
    
    // Register Movement (0x10-0x1F)
    OP_MOVE = 0x10,              // r_dest = r_src
    OP_SWAP,                     // swap(r_a, r_b)
    OP_LOAD_REG_0,               // Load from register bank
    OP_LOAD_REG_1,
    OP_STORE_REG_0,              // Store to register bank
    OP_STORE_REG_1,
    
    // Arithmetic (0x20-0x2F)
    OP_ADD = 0x20,               // r_dest = r_left + r_right
    OP_SUB,                      // r_dest = r_left - r_right
    OP_MUL,                      // r_dest = r_left * r_right
    OP_DIV,                      // r_dest = r_left / r_right
    OP_MOD,                      // r_dest = r_left % r_right
    OP_NEG,                      // r_dest = -r_src
    OP_INC,                      // r_dest++
    OP_DEC,                      // r_dest--
    OP_POW,                      // r_dest = pow(r_left, r_right)
    
    // Bitwise (0x30-0x3F)
    OP_BIT_AND = 0x30,           // r_dest = r_left & r_right
    OP_BIT_OR,                   // r_dest = r_left | r_right
    OP_BIT_XOR,                  // r_dest = r_left ^ r_right
    OP_BIT_NOT,                  // r_dest = ~r_src
    OP_SHL,                      // r_dest = r_left << r_right
    OP_SHR,                      // r_dest = r_left >> r_right
    OP_SHR_U,                    // r_dest = r_left >>> r_right (unsigned)
    
    // Comparison (0x40-0x4F)
    OP_EQ = 0x40,                // r_dest = r_left == r_right
    OP_NEQ,                      // r_dest = r_left != r_right
    OP_LT,                       // r_dest = r_left < r_right
    OP_LTE,                      // r_dest = r_left <= r_right
    OP_GT,                       // r_dest = r_left > r_right
    OP_GTE,                      // r_dest = r_left >= r_right
    OP_STRICT_EQ,                // r_dest = r_left === r_right
    OP_STRICT_NEQ,               // r_dest = r_left !== r_right
    OP_COMPARE,                  // Generic compare (-1, 0, 1)
    
    // Control Flow (0x50-0x5F)
    OP_JMP = 0x50,               // pc += offset
    OP_JMP_COND,                 // if (r_cond) pc += offset
    OP_JMP_NOT_COND,             // if (!r_cond) pc += offset
    OP_JMP_EQ,                   // if (r_left == r_right) pc += offset
    OP_JMP_NEQ,                  // if (r_left != r_right) pc += offset
    OP_JMP_LT,                   // if (r_left < r_right) pc += offset
    OP_CALL,                     // r_ret = r_func(r_arg1, r_arg2, ...)
    OP_CALL_NATIVE,              // Call native bridge function
    OP_RETURN,                   // return r_val
    OP_THROW,                    // throw r_val
    OP_TRY_START,                // Begin try block
    OP_TRY_END,                  // End try block
    OP_ENTER_SCOPE,              // Enter new variable scope
    OP_EXIT_SCOPE,               // Exit variable scope
    
    // Object Operations (0x60-0x7F) - With IC
    OP_GET_PROP = 0x60,          // r_dest = r_obj.property (IC slot follows)
    OP_SET_PROP,                 // r_obj.property = r_val (IC slot follows)
    OP_GET_ELEM,                 // r_dest = r_obj[r_index]
    OP_SET_ELEM,                 // r_obj[r_index] = r_val
    OP_DELETE_PROP,              // delete r_obj.property
    OP_DELETE_ELEM,              // delete r_obj[r_index]
    OP_IN,                       // r_dest = r_prop in r_obj
    OP_INSTANCEOF,               // r_dest = r_obj instanceof r_ctor
    OP_NEW,                      // r_dest = new r_ctor(r_arg1, ...)
    OP_TYPEOF,                   // r_dest = typeof r_val
    OP_HAS_OWN_PROP,             // r_dest = r_obj.hasOwnProperty(r_prop)
    OP_GET_PROTO,                // r_dest = r_obj.__proto__
    OP_SET_PROTO,                // r_obj.__proto__ = r_val
    
    // Array/Object Literals (0x80-0x8F)
    OP_CREATE_ARRAY = 0x80,      // r_dest = [] (size hint)
    OP_CREATE_OBJECT,            // r_dest = {}
    OP_ARRAY_PUSH,                 // r_array.push(r_val)
    OP_ARRAY_POP,                  // r_array.pop()
    OP_ARRAY_GET_LEN,            // r_dest = r_array.length
    OP_ARRAY_SET_LEN,            // r_array.length = r_val
    OP_OBJECT_SET,                 // r_obj[key] = val (for literals)
    OP_OBJECT_GET_KEYS,            // r_dest = Object.keys(r_obj)
    
    // Function Operations (0x90-0x9F)
    OP_CREATE_FUNC = 0x90,       // r_dest = function
    OP_BIND_THIS,                // r_dest = r_func.bind(r_this)
    OP_APPLY,                    // r_dest = r_func.apply(r_this, r_args)
    OP_CALL_METHOD,              // r_obj.method(args) - optimized
    OP_GET_CLOSURE,              // r_dest = closure[slot]
    OP_SET_CLOSURE,              // closure[slot] = r_val
    
    // Iteration (0xA0-0xAF)
    OP_ITER_START = 0xA0,        // r_iter = r_obj[Symbol.iterator]()
    OP_ITER_NEXT,                // r_dest = r_iter.next()
    OP_ITER_HAS_NEXT,            // r_dest = !r_iter.done
    OP_FOR_IN_START,             // Setup for-in loop
    OP_FOR_IN_NEXT,              // Get next for-in key
    OP_FOR_OF_START,             // Setup for-of loop
    OP_FOR_OF_NEXT,              // Get next for-of value
    
    // Async Operations (0xB0-0xBF)
    OP_AWAIT = 0xB0,             // await r_promise
    OP_PROMISE_RESOLVE,          // r_dest = Promise.resolve(r_val)
    OP_PROMISE_REJECT,             // r_dest = Promise.reject(r_val)
    OP_ASYNC_CALL,                 // Non-blocking call, returns Promise
    OP_YIELD,                    // yield r_val (generators)
    OP_YIELD_STAR,                 // yield* r_iter (generators)
    
    // Optimized operations (0xC0-0xCF)
    OP_ADD_INT = 0xC0,           // Integer-only add (fast path)
    OP_SUB_INT,                  // Integer-only sub
    OP_MUL_INT,                  // Integer-only mul
    OP_INC_LOCAL,                // Increment local variable
    OP_DEC_LOCAL,                // Decrement local variable
    OP_GET_LOCAL,                // Get local by index
    OP_SET_LOCAL,                // Set local by index
    OP_GET_GLOBAL,               // Get global by name
    OP_SET_GLOBAL,               // Set global by name
    
    // Debug (0xF0-0xFF)
    OP_DEBUG_BREAK = 0xF0,       // Breakpoint
    OP_DEBUG_LOG,                // console.log(r_val)
    OP_ASSERT,                   // Runtime assertion
    OP_PROFILE_START,            // Start profiling
    OP_PROFILE_END,              // End profiling
    OP_NOP = 0xFF                // No operation
};

// Get opcode name for disassembly
const char* GetOpcodeName(Opcode op);

// Get opcode category
enum class OpcodeCategory {
    Constant,
    Register,
    Arithmetic,
    Bitwise,
    Comparison,
    ControlFlow,
    Object,
    Array,
    Function,
    Iteration,
    Async,
    Optimized,
    Debug,
    Other
};

OpcodeCategory GetOpcodeCategory(Opcode op);

// ============================================================================
// Instruction Encoding
// ============================================================================

// Fixed-width instruction: 4 bytes
// [Opcode:8][Dest Reg:4][Src A:4][Src B:4][Reserved:12]
#pragma pack(push, 1)
struct Instruction {
    uint8_t opcode;
    uint8_t dest_reg : 4;
    uint8_t src_a : 4;
    uint8_t src_b : 4;
    uint8_t reserved_low : 4;   // Split reserved into two 4-bit fields
    uint8_t reserved_high : 8;  // to avoid bitfield packing issues
    
    Instruction() : opcode(0), dest_reg(0), src_a(0), src_b(0), reserved_low(0), reserved_high(0) {}
    Instruction(Opcode op, uint8_t dst, uint8_t a, uint8_t b)
        : opcode(static_cast<uint8_t>(op)), dest_reg(dst), src_a(a), src_b(b), reserved_low(0), reserved_high(0) {}
    
    uint16_t reserved() const { return static_cast<uint16_t>(reserved_low) | (static_cast<uint16_t>(reserved_high) << 4); }
};
#pragma pack(pop)

static_assert(sizeof(Instruction) == 4, "Instruction must be 4 bytes");

// Extended instruction format for large constants
// [Opcode:8][Dest Reg:4][Type:4][Length:16][Payload...]
struct ExtendedInstruction {
    uint8_t opcode;
    uint8_t dest_reg : 4;
    uint8_t type : 4;      // Payload type
    uint16_t length;       // Payload length in bytes
    // Payload follows...
};

// Extended instruction types
constexpr uint8_t EXT_TYPE_CONST_IDX = 0;     // Constant pool index
constexpr uint8_t EXT_TYPE_STRING_IDX = 1;      // String table index
constexpr uint8_t EXT_TYPE_JUMP_OFFSET = 2;     // Jump offset (signed 32-bit)
constexpr uint8_t EXT_TYPE_INT32 = 3;           // Immediate int32
constexpr uint8_t EXT_TYPE_FLOAT64 = 4;         // Immediate double

// ============================================================================
// Constant Pool
// ============================================================================

enum class ConstantType : uint8_t {
    Null = 0,
    Undefined,
    Boolean,
    Int32,
    Float64,
    String,
    FunctionRef,    // Reference to function bytecode
    ObjectShape,    // Object shape/hidden class
};

struct Constant {
    ConstantType type;
    union {
        bool bool_value;
        int32_t int32_value;
        double float64_value;
        uint32_t string_offset;   // Offset into string table
        uint32_t function_offset; // Offset to function bytecode
        uint32_t shape_id;        // Shape identifier
    };
    
    Constant() : type(ConstantType::Null), int32_value(0) {}
};

// Constant pool entry with type tag
struct ConstantPoolEntry {
    ConstantType type;
    std::vector<uint8_t> data;  // Variable-length data
};

// ============================================================================
// Debug Information
// ============================================================================

struct LineInfoEntry {
    uint32_t bytecode_offset;  // Offset in bytecode
    uint32_t line_number;        // Source line number
    uint32_t column;             // Source column
};

struct DebugInfo {
    std::vector<LineInfoEntry> line_table;
    std::string source_filename;
    std::string source_map;      // Optional source map
};

// ============================================================================
// Bytecode Module
// ============================================================================

class BytecodeModule {
public:
    BytecodeModule();
    
    // Serialization
    std::vector<uint8_t> Serialize() const;
    bool Deserialize(const uint8_t* data, size_t size);
    bool LoadFromFile(const std::string& filename);
    bool SaveToFile(const std::string& filename) const;
    
    // Code section
    void AppendInstruction(const Instruction& inst);
    void AppendInstructions(const std::vector<Instruction>& insts);
    const std::vector<Instruction>& GetCode() const { return code_; }
    
    // Constant pool
    uint32_t AddConstant(const Constant& constant);
    uint32_t AddString(const std::string& str);
    const Constant& GetConstant(uint32_t index) const;
    std::string GetString(uint32_t index) const;
    
    // Inline cache slots
    uint32_t AllocateICSlot();
    uint32_t GetICSlotCount() const { return ic_slot_count_; }
    
    // Debug info
    void AddLineInfo(uint32_t bytecode_offset, uint32_t line, uint32_t col);
    bool HasDebugInfo() const { return !debug_info_.line_table.empty(); }
    
    // Metadata
    void SetStrictMode(bool strict) { strict_mode_ = strict; }
    bool IsStrictMode() const { return strict_mode_; }
    
    // Disassembly
    std::string Disassemble() const;
    
private:
    BytecodeHeader header_;
    std::vector<Instruction> code_;
    std::vector<Constant> constant_pool_;
    std::vector<char> string_table_;  // Null-terminated strings
    uint32_t ic_slot_count_;
    DebugInfo debug_info_;
    bool strict_mode_;
    
    // String table helpers
    uint32_t FindString(const std::string& str) const;
    void BuildStringTable();
};

// ============================================================================
// Disassembler
// ============================================================================

class Disassembler {
public:
    Disassembler(const BytecodeModule& module);
    
    std::string Disassemble() const;
    std::string DisassembleInstruction(size_t index) const;
    
private:
    const BytecodeModule& module_;
    
    std::string FormatInstruction(const Instruction& inst, size_t offset) const;
    std::string FormatOperand(uint8_t reg) const;
};

} // namespace Bytecode
} // namespace Script
} // namespace RawrXD
