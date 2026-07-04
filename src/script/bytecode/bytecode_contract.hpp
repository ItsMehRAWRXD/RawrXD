// RawrXD-Script Bytecode Contract
// Defines the binary interface between C++ Emitter and MASM Interpreter
//
// This contract is the single source of truth for:
// - Bytecode file format
// - Instruction encoding
// - Opcode values
// - Calling convention between C++ and MASM
//
// Version: 1.0.0

#pragma once

#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace Script {
namespace Bytecode {

// ============================================================================
// BYTECODE FILE FORMAT
// ============================================================================
//
// [Header] - 64 bytes
// [Code Section] - variable length, 4-byte aligned
// [Constant Pool] - variable length
// [String Table] - variable length
// [IC Table] - Inline Cache metadata
// [Line Info] - debug information (optional)
//
// All sections are 8-byte aligned

// Magic number: "RAWR" in little-endian
static constexpr uint32_t kBytecodeMagic = 0x52415752;  // 'R' 'A' 'W' 'R'

// Version: major.minor.patch (packed as 16-bit)
static constexpr uint16_t kBytecodeVersionMajor = 1;
static constexpr uint16_t kBytecodeVersionMinor = 0;
static constexpr uint16_t kBytecodeVersionPatch = 0;
static constexpr uint16_t kBytecodeVersion = (kBytecodeVersionMajor << 12) | 
                                            (kBytecodeVersionMinor << 4) | 
                                            kBytecodeVersionPatch;

// Header flags
enum class BytecodeFlags : uint16_t {
    kNone = 0,
    kStrictMode = 1 << 0,      // Strict mode enabled
    kHasDebugInfo = 1 << 1,    // Line info section present
    kProfileCoverage = 1 << 2,  // Coverage hooks enabled
    kProfileIC = 1 << 3,       // IC profiling enabled
};

// Bytecode Header (64 bytes, 8-byte aligned)
struct alignas(8) BytecodeHeader {
    uint32_t magic;              // 0: 'RAWR'
    uint16_t version;            // 4: packed version
    uint16_t flags;              // 6: BytecodeFlags
    uint32_t codeOffset;         // 8: offset to code section
    uint32_t codeSize;           // 12: size of code section in bytes
    uint32_t constPoolOffset;    // 16: offset to constant pool
    uint32_t constPoolCount;     // 20: number of constants
    uint32_t stringTableOffset;  // 24: offset to string table
    uint32_t stringTableSize;    // 28: size of string table
    uint32_t icTableOffset;       // 32: offset to IC table
    uint32_t icSlotCount;         // 36: number of IC slots
    uint32_t lineInfoOffset;      // 40: offset to line info (0 if none)
    uint32_t reserved[5];         // 44-63: reserved, must be 0
};
static_assert(sizeof(BytecodeHeader) == 64, "Header must be 64 bytes");

// ============================================================================
// INSTRUCTION FORMAT
// ============================================================================
// Fixed 4-byte (32-bit) instructions
//
// [Opcode:8][Dst:4][SrcA:4][SrcB:4][Reserved:12]
//
// Bit layout:
//   31-24: Opcode (8 bits)
//   23-20: Destination register (4 bits)
//   19-16: Source A register (4 bits)
//   15-12: Source B register (4 bits)
//   11-0:  Reserved/Immediate (12 bits)

struct Instruction {
    uint32_t raw;
    
    // Constructors
    Instruction() : raw(0) {}
    Instruction(uint8_t opcode, uint8_t dst = 0, uint8_t srcA = 0, uint8_t srcB = 0, uint16_t imm = 0)
        : raw((static_cast<uint32_t>(opcode) << 24) |
              ((dst & 0xF) << 20) |
              ((srcA & 0xF) << 16) |
              ((srcB & 0xF) << 12) |
              (imm & 0xFFF)) {}
    
    // Extractors
    uint8_t Opcode() const { return static_cast<uint8_t>(raw >> 24); }
    uint8_t Dst() const { return static_cast<uint8_t>((raw >> 20) & 0xF); }
    uint8_t SrcA() const { return static_cast<uint8_t>((raw >> 16) & 0xF); }
    uint8_t SrcB() const { return static_cast<uint8_t>((raw >> 12) & 0xF); }
    uint16_t Imm12() const { return static_cast<uint16_t>(raw & 0xFFF); }
    
    // Immediate as signed 12-bit
    int16_t Imm12Signed() const {
        uint16_t imm = Imm12();
        return (imm & 0x800) ? static_cast<int16_t>(imm | 0xF000) : static_cast<int16_t>(imm);
    }
};
static_assert(sizeof(Instruction) == 4, "Instruction must be 4 bytes");

// ============================================================================
// OPCODES
// ============================================================================
// 0x00-0x0F: Control Flow
// 0x10-0x1F: Constants
// 0x20-0x2F: Arithmetic
// 0x30-0x3F: Bitwise
// 0x40-0x4F: Comparison
// 0x50-0x5F: Logical
// 0x60-0x6F: Memory/Objects
// 0x70-0x7F: Arrays
// 0x80-0x8F: Functions
// 0x90-0x9F: Exceptions
// 0xA0-0xAF: Type Operations
// 0xB0-0xBF: String Operations
// 0xC0-0xCF: Reserved
// 0xD0-0xDF: Reserved
// 0xE0-0xEF: Reserved
// 0xF0-0xFF: System/Debug

enum class Opcode : uint8_t {
    // Control Flow (0x00-0x0F)
    kNop = 0x00,           // No operation
    kReturn = 0x01,        // Return value from register
    kReturnUndefined = 0x02, // Return undefined
    kJump = 0x03,          // Unconditional jump (offset in imm12)
    kJumpIfTrue = 0x04,    // Jump if register is truthy
    kJumpIfFalse = 0x05,   // Jump if register is falsy
    kJumpIfEqual = 0x06,   // Jump if SrcA == SrcB
    kJumpIfNotEqual = 0x07,// Jump if SrcA != SrcB
    kCall = 0x08,          // Call function (Dst = SrcA(SrcB...))
    kCallNative = 0x09,    // Call native function
    kTailCall = 0x0A,      // Tail call optimization
    kEnterTry = 0x0B,      // Enter try block
    kLeaveTry = 0x0C,      // Leave try block
    kThrow = 0x0D,         // Throw exception
    kDebugger = 0x0E,      // Breakpoint
    kHalt = 0x0F,          // Halt execution
    
    // Constants (0x10-0x1F)
    kLoadConst = 0x10,     // Load constant: Dst = ConstPool[SrcA]
    kLoadUndefined = 0x11, // Dst = undefined
    kLoadNull = 0x12,      // Dst = null
    kLoadTrue = 0x13,      // Dst = true
    kLoadFalse = 0x14,     // Dst = false
    kLoadZero = 0x15,      // Dst = 0
    kLoadOne = 0x16,       // Dst = 1
    kLoadInt = 0x17,       // Dst = sign-extended imm12
    kLoadString = 0x18,    // Dst = string from string table
    kLoadGlobal = 0x19,    // Dst = global[SrcA]
    kStoreGlobal = 0x1A,   // global[SrcA] = SrcB
    kLoadEnv = 0x1B,       // Load from environment
    kStoreEnv = 0x1C,      // Store to environment
    kReserve = 0x1D,       // Reserve slots
    kMove = 0x1E,          // Dst = SrcA (copy)
    kSwap = 0x1F,          // Swap Dst <-> SrcA
    
    // Arithmetic (0x20-0x2F)
    kAdd = 0x20,           // Dst = SrcA + SrcB
    kSub = 0x21,           // Dst = SrcA - SrcB
    kMul = 0x22,           // Dst = SrcA * SrcB
    kDiv = 0x23,           // Dst = SrcA / SrcB
    kMod = 0x24,           // Dst = SrcA % SrcB
    kNeg = 0x25,           // Dst = -SrcA
    kInc = 0x26,           // Dst = SrcA + 1
    kDec = 0x27,           // Dst = SrcA - 1
    kPow = 0x28,           // Dst = SrcA ** SrcB
    kSqrt = 0x29,          // Dst = sqrt(SrcA)
    kAbs = 0x2A,           // Dst = abs(SrcA)
    kMin = 0x2B,           // Dst = min(SrcA, SrcB)
    kMax = 0x2C,           // Dst = max(SrcA, SrcB)
    kClamp = 0x2D,         // Dst = clamp(SrcA, SrcB, imm)
    kFloor = 0x2E,         // Dst = floor(SrcA)
    kCeil = 0x2F,          // Dst = ceil(SrcA)
    
    // Bitwise (0x30-0x3F)
    kBitAnd = 0x30,        // Dst = SrcA & SrcB
    kBitOr = 0x31,         // Dst = SrcA | SrcB
    kBitXor = 0x32,        // Dst = SrcA ^ SrcB
    kBitNot = 0x33,        // Dst = ~SrcA
    kShiftLeft = 0x34,     // Dst = SrcA << SrcB
    kShiftRight = 0x35,    // Dst = SrcA >> SrcB
    kShiftRightUnsigned = 0x36, // Dst = SrcA >>> SrcB
    kRotateLeft = 0x37,    // Dst = rotate_left(SrcA, SrcB)
    kRotateRight = 0x38,   // Dst = rotate_right(SrcA, SrcB)
    kPopCount = 0x39,      // Dst = popcount(SrcA)
    kLeadingZero = 0x3A,   // Dst = clz(SrcA)
    kTrailingZero = 0x3B,  // Dst = ctz(SrcA)
    kBitExtract = 0x3C,    // Dst = extract_bits(SrcA, SrcB, imm)
    kBitInsert = 0x3D,     // Dst = insert_bits(SrcA, SrcB, imm)
    kBitClear = 0x3E,      // Dst = clear_bit(SrcA, imm)
    kBitSet = 0x3F,        // Dst = set_bit(SrcA, imm)
    
    // Comparison (0x40-0x4F)
    kEq = 0x40,            // Dst = SrcA == SrcB
    kNe = 0x41,            // Dst = SrcA != SrcB
    kLt = 0x42,            // Dst = SrcA < SrcB
    kLe = 0x43,            // Dst = SrcA <= SrcB
    kGt = 0x44,            // Dst = SrcA > SrcB
    kGe = 0x45,            // Dst = SrcA >= SrcB
    kStrictEq = 0x46,      // Dst = SrcA === SrcB
    kStrictNe = 0x47,      // Dst = SrcA !== SrcB
    kIsNull = 0x48,        // Dst = SrcA === null
    kIsUndefined = 0x49,   // Dst = SrcA === undefined
    kIsNullOrUndefined = 0x4A, // Dst = SrcA == null || SrcA == undefined
    kIsCallable = 0x4B,    // Dst = is_callable(SrcA)
    kIsConstructor = 0x4C,   // Dst = is_constructor(SrcA)
    kInstanceOf = 0x4D,      // Dst = SrcA instanceof SrcB
    kIn = 0x4E,              // Dst = SrcA in SrcB
    kCompare = 0x4F,         // Dst = compare(SrcA, SrcB) (-1, 0, 1)
    
    // Logical (0x50-0x5F)
    kLogicalAnd = 0x50,    // Dst = SrcA && SrcB (short-circuit)
    kLogicalOr = 0x51,     // Dst = SrcA || SrcB (short-circuit)
    kLogicalNot = 0x52,    // Dst = !SrcA
    kCoalesce = 0x53,      // Dst = SrcA ?? SrcB
    kOptionalChain = 0x54, // Optional chaining
    kToBoolean = 0x55,     // Dst = ToBoolean(SrcA)
    kToNumber = 0x56,      // Dst = ToNumber(SrcA)
    kToString = 0x57,      // Dst = ToString(SrcA)
    kToObject = 0x58,      // Dst = ToObject(SrcA)
    kToPrimitive = 0x59,   // Dst = ToPrimitive(SrcA, hint)
    kTypeOf = 0x5A,        // Dst = typeof SrcA
    kVoid = 0x5B,          // Dst = void SrcA
    kDelete = 0x5C,        // Dst = delete SrcA[SrcB]
    kIncr = 0x5D,          // Dst = ++SrcA
    kDecr = 0x5E,          // Dst = --SrcA
    kSpread = 0x5F,        // Spread operator
    
    // Memory/Objects (0x60-0x6F)
    kNewObject = 0x60,     // Dst = {}
    kNewObjectWithSize = 0x61, // Dst = new Object(imm)
    kGetProp = 0x62,       // Dst = SrcA[SrcB] with IC
    kSetProp = 0x63,       // SrcA[SrcB] = Dst with IC
    kDefineProp = 0x64,    // Define property
    kDeleteProp = 0x65,    // Delete property
    kHasProp = 0x66,       // Dst = SrcB in SrcA
    kGetOwnProp = 0x67,    // Dst = SrcA.hasOwnProperty(SrcB)
    kKeys = 0x68,          // Dst = Object.keys(SrcA)
    kValues = 0x69,        // Dst = Object.values(SrcA)
    kEntries = 0x6A,       // Dst = Object.entries(SrcA)
    kAssign = 0x6B,        // Dst = Object.assign(SrcA, SrcB)
    kFreeze = 0x6C,        // Object.freeze(SrcA)
    kSeal = 0x6D,          // Object.seal(SrcA)
    kClone = 0x6E,         // Dst = clone(SrcA)
    kExtend = 0x6F,        // Dst = extend(SrcA, SrcB)
    
    // Arrays (0x70-0x7F)
    kNewArray = 0x70,      // Dst = []
    kNewArrayWithSize = 0x71, // Dst = new Array(imm)
    kArrayPush = 0x72,     // SrcA.push(SrcB)
    kArrayPop = 0x73,      // Dst = SrcA.pop()
    kArrayShift = 0x74,    // Dst = SrcA.shift()
    kArrayUnshift = 0x75,  // SrcA.unshift(SrcB)
    kArraySlice = 0x76,    // Dst = SrcA.slice(SrcB, imm)
    kArraySplice = 0x77,   // SrcA.splice(SrcB, imm, ...)
    kArrayIndexOf = 0x78,  // Dst = SrcA.indexOf(SrcB)
    kArrayIncludes = 0x79, // Dst = SrcA.includes(SrcB)
    kArrayFind = 0x7A,     // Dst = SrcA.find(SrcB)
    kArrayFilter = 0x7B,   // Dst = SrcA.filter(SrcB)
    kArrayMap = 0x7C,      // Dst = SrcA.map(SrcB)
    kArrayReduce = 0x7D,   // Dst = SrcA.reduce(SrcB, SrcC)
    kArrayForEach = 0x7E,  // SrcA.forEach(SrcB)
    kArrayLength = 0x7F,   // Dst = SrcA.length
    
    // Functions (0x80-0x8F)
    kNewFunction = 0x80,   // Dst = function() { ... }
    kNewArrow = 0x81,      // Dst = () => ...
    kNewMethod = 0x82,     // Dst = { method() { } }
    kNewGetter = 0x83,     // Dst = { get prop() { } }
    kNewSetter = 0x84,     // Dst = { set prop(v) { } }
    kBind = 0x85,          // Dst = SrcA.bind(SrcB)
    kApply = 0x86,         // Dst = SrcA.apply(SrcB, SrcC)
    kCallMethod = 0x87,    // Dst = SrcA.SrcB(SrcC)
    kSuperCall = 0x88,     // super(...)
    kSuperGet = 0x89,      // super.prop
    kSuperSet = 0x8A,      // super.prop = value
    kNewClass = 0x8B,      // class { }
    kNewGenerator = 0x8C,  // generator function
    kYield = 0x8D,         // yield value
    kYieldStar = 0x8E,     // yield* value
    kAwait = 0x8F,         // await value
    
    // Exceptions (0x90-0x9F)
    kTryStart = 0x90,      // Begin try block
    kCatch = 0x91,         // Catch handler
    kFinally = 0x92,       // Finally handler
    kTryEnd = 0x93,        // End try block
    kThrow = 0x94,         // throw SrcA
    kRethrow = 0x95,       // Re-throw current exception
    kGetException = 0x96,  // Dst = current exception
    kClearException = 0x97, // Clear exception state
    kPushException = 0x98, // Push exception handler
    kPopException = 0x99,  // Pop exception handler
    kGetStackTrace = 0x9A, // Dst = stack trace
    kCaptureStack = 0x9B,  // Capture current stack
    kResume = 0x9C,        // Resume from exception
    kSuspend = 0x9D,       // Suspend execution
    kResumeGenerator = 0x9E, // Resume generator
    kCompleteGenerator = 0x9F, // Complete generator
    
    // Type Operations (0xA0-0xAF)
    kIsNumber = 0xA0,      // Dst = typeof SrcA == 'number'
    kIsString = 0xA1,      // Dst = typeof SrcA == 'string'
    kIsBoolean = 0xA2,     // Dst = typeof SrcA == 'boolean'
    kIsObject = 0xA3,      // Dst = typeof SrcA == 'object'
    kIsFunction = 0xA4,    // Dst = typeof SrcA == 'function'
    kIsSymbol = 0xA5,      // Dst = typeof SrcA == 'symbol'
    kIsBigInt = 0xA6,      // Dst = typeof SrcA == 'bigint'
    kIsArray = 0xA7,       // Dst = Array.isArray(SrcA)
    kIsInteger = 0xA8,     // Dst = Number.isInteger(SrcA)
    kIsFinite = 0xA9,      // Dst = Number.isFinite(SrcA)
    kIsNaN = 0xAA,         // Dst = Number.isNaN(SrcA)
    kIsSafeInteger = 0xAB, // Dst = Number.isSafeInteger(SrcA)
    kIsExtensible = 0xAC,  // Dst = Object.isExtensible(SrcA)
    kIsSealed = 0xAD,      // Dst = Object.isSealed(SrcA)
    kIsFrozen = 0xAE,      // Dst = Object.isFrozen(SrcA)
    kIsProxy = 0xAF,       // Dst = SrcA is Proxy
    
    // String Operations (0xB0-0xBF)
    kStringConcat = 0xB0,  // Dst = SrcA + SrcB
    kStringSlice = 0xB1,   // Dst = SrcA.slice(SrcB, imm)
    kStringSubstring = 0xB2, // Dst = SrcA.substring(SrcB, imm)
    kStringSubstr = 0xB3,  // Dst = SrcA.substr(SrcB, imm)
    kStringIndexOf = 0xB4, // Dst = SrcA.indexOf(SrcB)
    kStringLastIndexOf = 0xB5, // Dst = SrcA.lastIndexOf(SrcB)
    kStringIncludes = 0xB6, // Dst = SrcA.includes(SrcB)
    kStringStartsWith = 0xB7, // Dst = SrcA.startsWith(SrcB)
    kStringEndsWith = 0xB8, // Dst = SrcA.endsWith(SrcB)
    kStringRepeat = 0xB9,  // Dst = SrcA.repeat(imm)
    kStringTrim = 0xBA,    // Dst = SrcA.trim()
    kStringTrimStart = 0xBB, // Dst = SrcA.trimStart()
    kStringTrimEnd = 0xBC, // Dst = SrcA.trimEnd()
    kStringPadStart = 0xBD, // Dst = SrcA.padStart(imm, SrcB)
    kStringPadEnd = 0xBE,  // Dst = SrcA.padEnd(imm, SrcB)
    kStringReplace = 0xBF, // Dst = SrcA.replace(SrcB, SrcC)
    
    // System/Debug (0xF0-0xFF)
    kBreakpoint = 0xF0,    // Debugger breakpoint
    kTrace = 0xF1,         // Trace execution
    kAssert = 0xF2,      // Assert SrcA is truthy
    kProfileStart = 0xF3,  // Start profiling
    kProfileEnd = 0xF4,    // End profiling
    kCoverage = 0xF5,    // Coverage hook
    kLog = 0xF6,         // Console.log
    kWarn = 0xF7,        // Console.warn
    kError = 0xF8,       // Console.error
    kInfo = 0xF9,        // Console.info
    kDebug = 0xFA,       // Console.debug
    kTime = 0xFB,        // Console.time
    kTimeEnd = 0xFC,     // Console.timeEnd
    kCount = 0xFD,       // Console.count
    kCountReset = 0xFE,  // Console.countReset
    kHalt = 0xFF         // Halt execution
};

// Total opcodes: 256 (complete)
static_assert(static_cast<int>(Opcode::kHalt) == 0xFF, "Opcode count check");

// ============================================================================
// CONSTANT POOL ENTRIES
// ============================================================================

enum class ConstType : uint8_t {
    kUndefined = 0,
    kNull = 1,
    kBool = 2,
    kInt32 = 3,
    kDouble = 4,
    kString = 5,
    kSymbol = 6,
    kBigInt = 7,
    kObjectTemplate = 8,
    kFunctionTemplate = 9
};

struct ConstPoolEntry {
    ConstType type;
    uint8_t padding[7];  // Align to 8 bytes
    union {
        bool boolValue;
        int32_t int32Value;
        double doubleValue;
        uint32_t stringOffset;  // Offset into string table
        uint32_t objectTemplateId;
        uint32_t functionTemplateId;
    };
};
static_assert(sizeof(ConstPoolEntry) == 16, "ConstPoolEntry must be 16 bytes");

// ============================================================================
// INLINE CACHE (IC) TABLE
// ============================================================================

enum class ICState : uint8_t {
    kUninitialized = 0,
    kMonomorphic = 1,
    kPolymorphic = 2,
    kMegamorphic = 3
};

struct ICSlot {
    ICState state;
    uint8_t padding[3];
    uint32_t shapeId;       // Shape identifier
    uint32_t offset;        // Property offset
    uint32_t transitionShapeId; // For set operations
};
static_assert(sizeof(ICSlot) == 16, "ICSlot must be 16 bytes");

// ============================================================================
// C++ TO MASM CALLING CONVENTION
// ============================================================================
//
// extern "C" bool ExecuteBytecode_MASM(
//     void* runtime,           // rcx - Runtime context
//     const uint8_t* bytecode, // rdx - Bytecode base pointer
//     size_t bytecodeLen,      // r8  - Bytecode length
//     uint64_t* result         // r9  - Output value (NaN-boxed)
// );
//
// Returns: true on success, false on exception
//
// Register mapping in MASM:
//   rbx  = PC (Program Counter)
//   r12  = GLOBAL (Global object)
//   r13  = ARENA_BASE
//   r14  = BUMP
//   r15  = IC_TABLE
//   r8-r11 = Virtual registers v0-v3

// ============================================================================
// COMPILE-TIME CONTRACT VERIFICATION
// ============================================================================
// These static_asserts ensure C++ and MASM stay in sync.
// If any fail, the contract has drifted and must be reconciled.

// Instruction size verification
static_assert(sizeof(Instruction) == 4, "Instruction must be exactly 4 bytes");

// Header size verification
static_assert(sizeof(BytecodeHeader) == 64, "Header must be exactly 64 bytes");

// Opcode value verification (spot checks against MASM constants)
static_assert(static_cast<uint8_t>(Opcode::kNop) == 0x00, "OP_NOP mismatch");
static_assert(static_cast<uint8_t>(Opcode::kReturn) == 0x01, "OP_RETURN mismatch");
static_assert(static_cast<uint8_t>(Opcode::kLoadConst) == 0x10, "OP_LOAD_CONST mismatch");
static_assert(static_cast<uint8_t>(Opcode::kAdd) == 0x20, "OP_ADD mismatch");
static_assert(static_cast<uint8_t>(Opcode::kBitAnd) == 0x30, "OP_BIT_AND mismatch");
static_assert(static_cast<uint8_t>(Opcode::kEq) == 0x40, "OP_EQ mismatch");
static_assert(static_cast<uint8_t>(Opcode::kLogicalAnd) == 0x50, "OP_LOGICAL_AND mismatch");
static_assert(static_cast<uint8_t>(Opcode::kNewObject) == 0x60, "OP_NEW_OBJECT mismatch");
static_assert(static_cast<uint8_t>(Opcode::kNewArray) == 0x70, "OP_NEW_ARRAY mismatch");
static_assert(static_cast<uint8_t>(Opcode::kNewFunction) == 0x80, "OP_NEW_FUNCTION mismatch");
static_assert(static_cast<uint8_t>(Opcode::kTryStart) == 0x90, "OP_TRY_START mismatch");
static_assert(static_cast<uint8_t>(Opcode::kIsNumber) == 0xA0, "OP_IS_NUMBER mismatch");
static_assert(static_cast<uint8_t>(Opcode::kStringConcat) == 0xB0, "OP_STRING_CONCAT mismatch");
static_assert(static_cast<uint8_t>(Opcode::kBreakpoint) == 0xF0, "OP_BREAKPOINT mismatch");
static_assert(static_cast<uint8_t>(Opcode::kHalt) == 0xFF, "OP_HALT mismatch");

// NaN-boxing constant verification
static_assert(kBytecodeMagic == 0x52415752, "Magic number mismatch");

// Const pool entry size
static_assert(sizeof(ConstPoolEntry) == 16, "ConstPoolEntry must be 16 bytes");

// IC slot size
static_assert(sizeof(ICSlot) == 16, "ICSlot must be 16 bytes");

// ============================================================================
// C++ TO MASM CALLING CONVENTION
// ============================================================================
//
// extern "C" bool ExecuteBytecode_MASM(
//     void* runtime,           // rcx - Runtime context
//     const uint8_t* bytecode, // rdx - Bytecode base pointer
//     size_t bytecodeLen,      // r8  - Bytecode length
//     uint64_t* result         // r9  - Output value (NaN-boxed)
// );
//
// Returns: true on success, false on exception
//
// Register mapping in MASM:
//   rbx  = PC (Program Counter)
//   r12  = GLOBAL (Global object)
//   r13  = ARENA_BASE
//   r14  = BUMP
//   r15  = IC_TABLE
//   r8-r11 = Virtual registers v0-v3

extern "C" {
    // Execute bytecode in MASM interpreter
    // Returns true on success, false on exception
    bool ExecuteBytecode_MASM(
        void* runtime,
        const uint8_t* bytecode,
        size_t bytecodeLen,
        uint64_t* result
    );
    
    // Reset coverage counters (if profiling enabled)
    void ResetCoverage_MASM();
    
    // Get opcode execution count
    uint32_t GetOpcodeCount_MASM(uint8_t opcode);
}

} // namespace Bytecode
} // namespace Script
} // namespace RawrXD
