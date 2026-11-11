/**
 * @file RawrCodex_Multi_v2.hpp
 * @brief Improved Multi-Architecture Decoder Interface
 * @description Separates decode semantics from presentation, uses backend registration
 * 
 * @version 2.0.0 - Architecture improvements based on review feedback
 * 
 * Key Changes from v1:
 * - Separated DecodedInstruction into RawInstruction + SemanticInstruction
 * - Removed fixed-size strings (mnemonic/operandsStr) - use enums + pretty-printer
 * - Added DecoderBackend registration table (plugin architecture)
 * - Added ABI validation framework
 * - Added fuzzing infrastructure
 * - Added malformed input handling
 */

#pragma once

#include <cstdint>
#include <cstddef>

// ============================================================================
// Version Information
// ============================================================================

#define RAWRCODEX_MULTI_VERSION_MAJOR 2
#define RAWRCODEX_MULTI_VERSION_MINOR 0
#define RAWRCODEX_MULTI_VERSION_PATCH 0

// ============================================================================
// Architecture Types (extensible via registration)
// ============================================================================

enum class ArchType : uint32_t {
    UNKNOWN     = 0,
    X86_32      = 1,
    X86_64      = 2,
    ARM_32      = 3,
    ARM_64      = 4,
    THUMB       = 5,
    THUMB2      = 6,
    MIPS_32     = 7,
    MIPS_64     = 8,
    RISCV_32    = 9,
    RISCV_64    = 10,
    // Extension points
    POWERPC_32  = 11,
    POWERPC_64  = 12,
    SPARC_32    = 13,
    SPARC_64    = 14,
    MAX_ARCH    = 15
};

// ============================================================================
// Instruction Classification (semantic, not textual)
// ============================================================================

enum class InstrClass : uint32_t {
    UNKNOWN         = 0,
    
    // Data processing
    DP_REG          = 1,    // Register-to-register
    DP_IMM          = 2,    // Immediate operation
    DP_SIMD         = 3,    // SIMD/vector operation
    
    // Memory
    LOAD            = 4,    // Memory load
    STORE           = 5,    // Memory store
    LOAD_MULTIPLE   = 6,    // Load multiple registers
    STORE_MULTIPLE  = 7,    // Store multiple registers
    
    // Control flow
    BRANCH          = 8,    // Unconditional branch
    BRANCH_COND     = 9,    // Conditional branch
    CALL            = 10,   // Subroutine call
    RETURN          = 11,   // Subroutine return
    INDIRECT_JUMP   = 12,   // Indirect branch/call
    
    // System
    SYSCALL         = 13,   // System call
    PRIVILEGED      = 14,   // Privileged instruction
    BARRIER         = 15,   // Memory barrier/fence
    
    // Special
    NOP             = 16,   // No operation
    DEBUG           = 17,   // Debug breakpoint
    UNDEFINED       = 18,   // Undefined/illegal
    PREFETCH        = 19,   // Prefetch hint
};

// ============================================================================
// Mnemonic Enumeration (replaces char mnemonic[32])
// ============================================================================

enum class Mnemonic : uint32_t {
    UNKNOWN = 0,
    
    // ARM64
    ARM64_NOP, ARM64_MOV, ARM64_MOVZ, ARM64_MOVN, ARM64_MOVK,
    ARM64_ADD, ARM64_SUB, ARM64_MUL, ARM64_DIV,
    ARM64_AND, ARM64_ORR, ARM64_EOR, ARM64_BIC,
    ARM64_LSL, ARM64_LSR, ARM64_ASR, ARM64_ROR,
    ARM64_LDR, ARM64_STR, ARM64_LDP, ARM64_STP,
    ARM64_B, ARM64_BL, ARM64_BR, ARM64_BLR, ARM64_RET,
    ARM64_CBZ, ARM64_CBNZ, ARM64_TBZ, ARM64_TBNZ,
    ARM64_CMP, ARM64_CMN, ARM64_TST,
    ARM64_ADR, ARM64_ADRP,
    ARM64_SVC, ARM64_HVC, ARM64_SMC,
    ARM64_MRS, ARM64_MSR,
    ARM64_DMB, ARM64_DSB, ARM64_ISB,
    
    // MIPS
    MIPS_NOP, MIPS_SLL, MIPS_SRL, MIPS_SRA,
    MIPS_ADD, MIPS_ADDI, MIPS_ADDU, MIPS_ADDIU,
    MIPS_SUB, MIPS_SUBU,
    MIPS_AND, MIPS_ANDI, MIPS_OR, MIPS_ORI, MIPS_XOR, MIPS_XORI, MIPS_NOR,
    MIPS_LUI,
    MIPS_LW, MIPS_LH, MIPS_LB, MIPS_LBU, MIPS_LHU,
    MIPS_SW, MIPS_SH, MIPS_SB,
    MIPS_J, MIPS_JAL, MIPS_JR, MIPS_JALR,
    MIPS_BEQ, MIPS_BNE, MIPS_BLEZ, MIPS_BGTZ,
    MIPS_SLT, MIPS_SLTI, MIPS_SLTU, MIPS_SLTIU,
    MIPS_SYSCALL, MIPS_BREAK, MIPS_SYNC,
    
    // RISC-V
    RISCV_NOP, RISCV_ADD, RISCV_ADDI,
    RISCV_SUB, RISCV_AND, RISCV_OR, RISCV_XOR,
    RISCV_ANDI, RISCV_ORI, RISCV_XORI,
    RISCV_SLL, RISCV_SRL, RISCV_SRA,
    RISCV_SLLI, RISCV_SRLI, RISCV_SRAI,
    RISCV_LUI, RISCV_AUIPC,
    RISCV_LB, RISCV_LH, RISCV_LW, RISCV_LD,
    RISCV_SB, RISCV_SH, RISCV_SW, RISCV_SD,
    RISCV_JAL, RISCV_JALR,
    RISCV_BEQ, RISCV_BNE, RISCV_BLT, RISCV_BGE, RISCV_BLTU, RISCV_BGEU,
    RISCV_SLT, RISCV_SLTI, RISCV_SLTU, RISCV_SLTIU,
    RISCV_ECALL, RISCV_EBREAK,
    RISCV_FENCE, RISCV_FENCE_I,
    
    // x64
    X64_NOP, X64_MOV, X64_PUSH, X64_POP,
    X64_ADD, X64_SUB, X64_MUL, X64_DIV, X64_IDIV,
    X64_AND, X64_OR, X64_XOR, X64_NOT, X64_NEG,
    X64_SHL, X64_SHR, X64_SAR,
    X64_CMP, X64_TEST,
    X64_JMP, X64_JCC, X64_CALL, X64_RET,
    X64_LEA,
    X64_SYSCALL, X64_SYSRET,
    
    MAX_MNEMONIC
};

// ============================================================================
// Operand Types
// ============================================================================

enum class OperandType : uint8_t {
    NONE        = 0,
    REGISTER    = 1,    // Integer register
    FP_REGISTER = 2,    // Floating-point register
    VECTOR_REG  = 3,    // SIMD/vector register
    IMMEDIATE   = 4,    // Immediate value
    MEMORY      = 5,    // Memory reference
    PC_RELATIVE = 6,    // PC-relative address
    LABEL       = 7,    // Branch target label
};

// ============================================================================
// Register Enumeration (architecture-agnostic)
// ============================================================================

enum class Register : uint32_t {
    NONE = 0,
    
    // ARM64: X0-X30, SP, XZR
    ARM64_X0 = 0x100, ARM64_X1, ARM64_X2, ARM64_X3,
    ARM64_X4, ARM64_X5, ARM64_X6, ARM64_X7,
    ARM64_X8, ARM64_X9, ARM64_X10, ARM64_X11,
    ARM64_X12, ARM64_X13, ARM64_X14, ARM64_X15,
    ARM64_X16, ARM64_X17, ARM64_X18, ARM64_X19,
    ARM64_X20, ARM64_X21, ARM64_X22, ARM64_X23,
    ARM64_X24, ARM64_X25, ARM64_X26, ARM64_X27,
    ARM64_X28, ARM64_X29, ARM64_X30,
    ARM64_SP, ARM64_XZR, ARM64_PC,
    
    // MIPS: $zero, $at, $v0-$v1, $a0-$a3, $t0-$t9, $s0-$s7, $k0-$k1, $gp, $sp, $fp, $ra
    MIPS_ZERO = 0x200, MIPS_AT,
    MIPS_V0, MIPS_V1,
    MIPS_A0, MIPS_A1, MIPS_A2, MIPS_A3,
    MIPS_T0, MIPS_T1, MIPS_T2, MIPS_T3, MIPS_T4, MIPS_T5, MIPS_T6, MIPS_T7,
    MIPS_S0, MIPS_S1, MIPS_S2, MIPS_S3, MIPS_S4, MIPS_S5, MIPS_S6, MIPS_S7,
    MIPS_T8, MIPS_T9,
    MIPS_K0, MIPS_K1,
    MIPS_GP, MIPS_SP, MIPS_FP, MIPS_RA,
    MIPS_PC,
    
    // RISC-V: x0-x31
    RISCV_X0 = 0x300,  // zero
    RISCV_X1,           // ra
    RISCV_X2,           // sp
    RISCV_X3,           // gp
    RISCV_X4,           // tp
    RISCV_X5, RISCV_X6, RISCV_X7,   // t0-t2
    RISCV_X8,           // s0/fp
    RISCV_X9,           // s1
    RISCV_X10, RISCV_X11,           // a0-a1
    RISCV_X12, RISCV_X13, RISCV_X14, RISCV_X15, // a2-a5
    RISCV_X16, RISCV_X17,           // a6-a7
    RISCV_X18,                      // s2
    RISCV_X19, RISCV_X20, RISCV_X21, RISCV_X22, // s3-s6
    RISCV_X23, RISCV_X24, RISCV_X25, RISCV_X26, // s7-s10
    RISCV_X27,                      // s11
    RISCV_X28, RISCV_X29, RISCV_X30, RISCV_X31, // t3-t6
    RISCV_PC,
    
    // x64: RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8-R15
    X64_RAX = 0x400, X64_RCX, X64_RDX, X64_RBX,
    X64_RSP, X64_RBP, X64_RSI, X64_RDI,
    X64_R8, X64_R9, X64_R10, X64_R11,
    X64_R12, X64_R13, X64_R14, X64_R15,
    X64_RIP,
};

// ============================================================================
// Raw Instruction (what was in the binary)
// ============================================================================

#pragma pack(push, 1)
struct RawInstruction {
    uint64_t    va;              // Virtual address
    uint32_t    length;          // Instruction length in bytes
    ArchType    arch;            // Architecture type
    uint8_t     bytes[16];       // Raw instruction bytes (max 16 for x86)
    uint32_t    encoding;        // First 4 bytes as integer (for quick lookup)
};
#pragma pack(pop)

// ============================================================================
// Operand (semantic representation)
// ============================================================================

#pragma pack(push, 1)
struct Operand {
    OperandType type;
    uint8_t     size;            // Size in bytes (1, 2, 4, 8, 16)
    
    union {
        Register    reg;         // For REGISTER types
        uint64_t    imm;         // For IMMEDIATE types
        int64_t     simm;        // Signed immediate
        double      fpImm;       // FP immediate
    };
    
    // Memory operand info
    struct {
        Register    base;
        Register    index;
        int32_t     scale;       // 1, 2, 4, 8
        int32_t     disp;        // Displacement
    } mem;
};
#pragma pack(pop)

// ============================================================================
// Semantic Instruction (decode result, no presentation)
// ============================================================================

#pragma pack(push, 1)
struct SemanticInstruction {
    // Identification
    Mnemonic        mnemonic;
    InstrClass      instrClass;
    ArchType        arch;
    
    // Opcode info
    uint32_t        opcode;      // Primary opcode field
    uint32_t        subOpcode;   // Secondary/sub-opcode
    
    // Operands (max 4)
    Operand         operands[4];
    uint8_t         operandCount;
    
    // Flags (semantic properties)
    struct {
        uint32_t isBranch        : 1;
        uint32_t isCall          : 1;
        uint32_t isReturn        : 1;
        uint32_t isConditional   : 1;
        uint32_t isLoad          : 1;
        uint32_t isStore         : 1;
        uint32_t isAtomic        : 1;
        uint32_t isPrivileged    : 1;
        uint32_t isSimd          : 1;
        uint32_t isFp            : 1;
        uint32_t modifiesFlags   : 1;
        uint32_t usesFlags       : 1;
        uint32_t isCompressed    : 1;  // RISC-V C, Thumb
        uint32_t isDelaySlot     : 1;  // MIPS delay slot
        uint32_t reserved        : 18;
    } flags;
    
    // Branch/call target (if known)
    uint64_t        targetAddr;
    
    // Condition code (for conditional instructions)
    uint8_t         condition;
};
#pragma pack(pop)

// ============================================================================
// Decoded Instruction (combined, for backward compatibility)
// ============================================================================

#pragma pack(push, 1)
struct DecodedInstruction {
    // Raw instruction data
    RawInstruction      raw;
    
    // Semantic decode
    SemanticInstruction semantic;
    
    // Pretty-printed (optional, generated on demand)
    // These are NOT filled by decoder - use PrettyPrinter
    char                cachedMnemonic[32];
    char                cachedOperands[64];
    bool                hasCachedText;
};
#pragma pack(pop)

static_assert(sizeof(DecodedInstruction) <= 512, "DecodedInstruction too large");

// ============================================================================
// Decode Result Status
// ============================================================================

enum class DecodeStatus : uint32_t {
    SUCCESS             = 0,
    ERROR_INVALID_ARCH  = 1,
    ERROR_INVALID_INPUT = 2,
    ERROR_TRUNCATED     = 3,    // Instruction bytes incomplete
    ERROR_MALFORMED     = 4,    // Invalid encoding
    ERROR_RESERVED      = 5,    // Reserved opcode
    ERROR_UNSUPPORTED   = 6,    // Valid but not yet implemented
    ERROR_BUFFER_SIZE   = 7,    // Output buffer too small
};

// ============================================================================
// Decoder Backend Interface (plugin architecture)
// ============================================================================

typedef DecodeStatus (*DecodeFn)(
    const RawInstruction* raw,
    SemanticInstruction* out
);

typedef uint32_t (*GetInstrLengthFn)(
    const uint8_t* bytes,
    size_t maxLength
);

typedef bool (*ValidateEncodingFn)(
    const uint8_t* bytes,
    size_t length
);

struct DecoderBackend {
    const char*         name;
    ArchType            arch;
    uint32_t            version;
    
    // Core functions
    DecodeFn            decode;
    GetInstrLengthFn    getLength;
    ValidateEncodingFn  validate;
    
    // Capabilities
    struct {
        uint32_t maxInstrLength;
        uint32_t minInstrLength;
        bool     hasVariableLength;
        bool     hasCompressed;
        bool     hasDelaySlots;
    } caps;
};

// ============================================================================
// Backend Registration API
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

// Register a decoder backend
__declspec(dllexport) bool Decoder_RegisterBackend(const DecoderBackend* backend);

// Get backend for architecture
__declspec(dllexport) const DecoderBackend* Decoder_GetBackend(ArchType arch);

// Unregister backend
__declspec(dllexport) bool Decoder_UnregisterBackend(ArchType arch);

// List all registered backends
__declspec(dllexport) uint32_t Decoder_ListBackends(const DecoderBackend** outArray, uint32_t maxCount);

#ifdef __cplusplus
}
#endif

// ============================================================================
// Core Decode API (unchanged from v1 for compatibility)
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

// Reference decoder (the oracle)
__declspec(dllexport) DecodeStatus ReferenceDecoder_Decode(
    ArchType arch,
    const uint8_t* bytes,
    size_t byteCount,
    DecodedInstruction* out
);

// Validate against reference
__declspec(dllexport) bool ReferenceDecoder_Validate(
    const DecodedInstruction* reference,
    const DecodedInstruction* optimized,
    char* mismatchReason,
    size_t reasonBufferSize
);

// Get architecture name
__declspec(dllimport) void GetArchitectureName(
    uint32_t archType,
    char* outputBuffer
);

// Compatibility wrappers (match RawrCodex.asm exports)
__declspec(dllimport) uint32_t RawrDisasm_Multi_Init(void* ctx);
__declspec(dllimport) uint32_t RawrDisasm_Multi_Decode(
    void* ctx,
    uint64_t va,
    const uint8_t* bytes,
    DecodedInstruction* out
);
__declspec(dllimport) uint32_t RawrDisasm_ARM_Decode(
    void* ctx,
    uint32_t archType,
    uint64_t va,
    const uint8_t* bytes,
    DecodedInstruction* out
);
__declspec(dllimport) uint32_t RawrDisasm_MIPS_Decode(
    void* ctx,
    uint32_t archType,
    uint64_t va,
    const uint8_t* bytes,
    DecodedInstruction* out
);
__declspec(dllimport) uint32_t RawrDisasm_RISCV_Decode(
    void* ctx,
    uint32_t archType,
    uint64_t va,
    const uint8_t* bytes,
    DecodedInstruction* out
);

// Emulator exports
__declspec(dllimport) void* RawrEmu_Multi_Create(uint32_t archType);
__declspec(dllimport) void RawrEmu_Multi_Destroy(void* emu);
__declspec(dllimport) uint32_t RawrEmu_Multi_Step(void* emu, DecodedInstruction* instr);
__declspec(dllimport) uint32_t RawrEmu_Multi_Run(void* emu, uint64_t maxCycles);

#ifdef __cplusplus
}
#endif

// ============================================================================
// Pretty Printer (separate from decoder)
// ============================================================================

#ifdef __cplusplus

namespace RawrCodex {

class PrettyPrinter {
public:
    // Format instruction to string
    static bool Format(const SemanticInstruction& instr, char* outBuffer, size_t bufferSize);
    static bool Format(const DecodedInstruction& instr, char* outBuffer, size_t bufferSize);
    
    // Format individual components
    static bool FormatMnemonic(Mnemonic mnem, ArchType arch, char* out, size_t size);
    static bool FormatOperand(const Operand& op, char* out, size_t size);
    static bool FormatRegister(Register reg, char* out, size_t size);
    
    // Configuration
    void SetUseHex(bool useHex) { m_useHex = useHex; }
    void SetUseSuffix(bool useSuffix) { m_useSuffix = useSuffix; }
    
private:
    bool m_useHex = true;
    bool m_useSuffix = false;
};

// ============================================================================
// ABI Validator (catches interface regressions)
// ============================================================================

class ABIValidator {
public:
    struct TestResult {
        const char* functionName;
        bool passed;
        char errorMessage[256];
    };
    
    // Validate all exported functions
    static bool ValidateAllExports(TestResult* results, uint32_t maxResults);
    
    // Validate specific function
    static bool ValidateExport(const char* name, TestResult* out);
    
    // Check register preservation
    static bool CheckRegisterPreservation(void* func, const char* name);
    
    // Check stack alignment
    static bool CheckStackAlignment(void* func, const char* name);
    
    // Check shadow space compliance
    static bool CheckShadowSpace(void* func, const char* name);
};

// ============================================================================
// Differential Validator (reference vs optimized)
// ============================================================================

class DifferentialValidator {
public:
    struct ValidationResult {
        bool match;
        const char* mismatchField;
        char expected[128];
        char actual[128];
    };
    
    // Compare two decoded instructions
    static bool Compare(const DecodedInstruction& ref,
                        const DecodedInstruction& opt,
                        ValidationResult* result);
    
    // Compare specific fields
    static bool CompareRaw(const RawInstruction& ref, const RawInstruction& opt);
    static bool CompareSemantic(const SemanticInstruction& ref, const SemanticInstruction& opt);
    
    // Run corpus test
    static bool RunCorpusTest(const char* corpusPath, uint32_t* passCount, uint32_t* failCount);
};

// ============================================================================
// Fuzzing Infrastructure
// ============================================================================

class FuzzingEngine {
public:
    struct FuzzConfig {
        uint64_t seed;
        uint64_t iterationCount;
        ArchType targetArch;
        bool testMalformed;
        bool testTruncated;
        bool testReserved;
    };
    
    struct FuzzResult {
        uint64_t iterations;
        uint64_t crashes;
        uint64_t hangs;
        uint64_t decodeFailures;
        uint64_t validationErrors;
    };
    
    // Run fuzzing session
    static bool Run(const FuzzConfig& config, FuzzResult* result);
    
    // Generate random valid instruction
    static bool GenerateValid(ArchType arch, uint8_t* outBytes, uint32_t* outLength);
    
    // Generate malformed instruction
    static bool GenerateMalformed(ArchType arch, uint8_t* outBytes, uint32_t* outLength);
    
    // Mutate existing instruction
    static bool Mutate(const uint8_t* original, uint32_t length, 
                       uint8_t* outBytes, uint32_t* outLength, uint64_t seed);
};

// ============================================================================
// Malformed Input Handler
// ============================================================================

class MalformedInputHandler {
public:
    // Test categories
    enum class TestCase {
        ILLEGAL_ENCODING,
        RESERVED_OPCODE,
        TRUNCATED_INSTRUCTION,
        MISALIGNED_ADDRESS,
        INVALID_PREFIX,
        OVERLONG_ENCODING,
        UNDEFINED_SUBCODE,
        PRIVILEGE_VIOLATION,
    };
    
    // Generate specific malformed input
    static bool Generate(TestCase testCase, ArchType arch, 
                         uint8_t* outBytes, uint32_t* outLength);
    
    // Test decoder resilience
    static bool TestResilience(DecodeFn decoder, ArchType arch,
                               uint32_t* crashCount, uint32_t* errorCount);
};

} // namespace RawrCodex

#endif // __cplusplus
