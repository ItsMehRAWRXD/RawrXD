/**
 * @file RawrCodex_Multi_Structured.hpp
 * @brief Structured multi-architecture decoder interface
 * @description Defines the DecodedInstruction structure and reference API
 * 
 * @version 1.0.0
 * @date 2026-07-07
 */

#pragma once

#include <cstdint>
#include <cstring>

// Architecture type constants (must match RawrCodex.asm)
enum class ArchType : uint32_t {
    X86_32      = 0,
    X86_64      = 1,
    ARM_32      = 2,
    ARM_64      = 3,
    THUMB       = 4,
    THUMB2      = 5,
    MIPS_32     = 6,
    MIPS_64     = 7,
    RISCV_32    = 8,
    RISCV_64    = 9
};

// Instruction class
enum class InstrClass : uint32_t {
    DP_REG      = 0,    // Data processing - register
    DP_IMM      = 1,    // Data processing - immediate
    BRANCH      = 2,    // Branch
    LDST        = 3,    // Load/store
    SIMD        = 4,    // SIMD/FP
    UNKNOWN     = 5     // Unknown/unclassified
};

// Instruction flags
enum InstrFlags : uint32_t {
    FLAG_NONE           = 0,
    FLAG_BRANCH         = 1 << 0,
    FLAG_CALL           = 1 << 1,
    FLAG_RETURN         = 1 << 2,
    FLAG_CONDITIONAL    = 1 << 3,
    FLAG_LOAD           = 1 << 4,
    FLAG_STORE          = 1 << 5,
    FLAG_PRIVILEGED     = 1 << 6,
    FLAG_COMPACT        = 1 << 7     // Compressed instruction (RISC-V, Thumb)
};

// Register identifier (architecture-agnostic)
enum class Register : uint32_t {
    NONE = 0,
    // x86-64
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    RIP, EFLAGS,
    // ARM64
    X0, X1, X2, X3, X4, X5, X6, X7,
    X8, X9, X10, X11, X12, X13, X14, X15,
    X16, X17, X18, X19, X20, X21, X22, X23,
    X24, X25, X26, X27, X28, X29, X30, SP, PC,
    // MIPS
    ZERO, AT, V0, V1, A0, A1, A2, A3,
    T0, T1, T2, T3, T4, T5, T6, T7,
    S0, S1, S2, S3, S4, S5, S6, S7,
    T8, T9, K0, K1, GP, SP_MIPS, FP, RA,
    // RISC-V
    X0_RV, X1_RV, X2_RV, X3_RV, X4_RV, X5_RV, X6_RV, X7_RV,
    X8_RV, X9_RV, X10_RV, X11_RV, X12_RV, X13_RV, X14_RV, X15_RV,
    X16_RV, X17_RV, X18_RV, X19_RV, X20_RV, X21_RV, X22_RV, X23_RV,
    X24_RV, X25_RV, X26_RV, X27_RV, X28_RV, X29_RV, X30_RV, X31_RV
};

// Operand type
enum class OperandType : uint32_t {
    NONE = 0,
    REGISTER,
    IMMEDIATE,
    MEMORY,
    LABEL
};

// Operand structure
struct Operand {
    OperandType type;
    Register reg;
    uint64_t immediate;
    int32_t displacement;
    Register baseReg;
    Register indexReg;
    uint8_t scale;
    
    Operand() : type(OperandType::NONE), reg(Register::NONE),
                immediate(0), displacement(0),
                baseReg(Register::NONE), indexReg(Register::NONE), scale(0) {}
};

// Decoded instruction structure (256 bytes, packed)
// This is the canonical representation used by the reference decoder
#pragma pack(push, 1)
struct DecodedInstruction {
    // Basic info (16 bytes)
    uint64_t va;                    // Virtual address
    uint32_t length;                // Instruction length in bytes
    ArchType arch;                  // Architecture type
    uint32_t _padding1;             // Padding to 16-byte boundary
    
    // Raw bytes (16 bytes)
    uint8_t rawBytes[16];           // Raw instruction bytes
    
    // Opcode info (16 bytes)
    uint32_t opcode;                // Primary opcode
    uint32_t subOpcode;             // Secondary/sub-opcode
    InstrClass instrClass;          // Instruction classification
    uint32_t flags;                 // Instruction flags
    
    // Registers (16 bytes)
    Register rd;                    // Destination register
    Register rs1;                   // Source register 1
    Register rs2;                   // Source register 2
    Register rs3;                   // Source register 3
    
    // Immediate values (16 bytes)
    uint64_t immediate;             // Immediate value
    int64_t signedImmediate;        // Signed immediate
    
    // Operands (64 bytes = 4 * 16 bytes per operand)
    Operand operands[4];
    
    // String representations (96 bytes)
    char mnemonic[32];              // Mnemonic string
    char operandsStr[64];           // Operands as string
    
    DecodedInstruction() {
        memset(this, 0, sizeof(*this));
    }
};
#pragma pack(pop)

static_assert(sizeof(DecodedInstruction) == 256, "DecodedInstruction must be exactly 256 bytes");

// =============================================================================
// Reference Decoder API (from RawrCodex_Multi_Reference.asm)
// =============================================================================

extern "C" {

/**
 * @brief Decode a single instruction using the reference decoder
 * @param arch Architecture type
 * @param bytes Pointer to instruction bytes
 * @param va Virtual address
 * @param outInstr Output DecodedInstruction structure
 * @return Instruction length in bytes, or 0 on error
 */
__declspec(dllimport) uint32_t ReferenceDecoder_DecodeInstruction(
    ArchType arch,
    const uint8_t* bytes,
    uint64_t va,
    DecodedInstruction* outInstr
);

/**
 * @brief Validate a decoded instruction against reference
 * @param reference Reference instruction
 * @param test Test instruction to validate
 * @return 1 if match, 0 if different
 */
__declspec(dllimport) int ReferenceDecoder_Validate(
    const DecodedInstruction* reference,
    const DecodedInstruction* test
);

/**
 * @brief Get architecture name string
 * @param arch Architecture type
 * @param buffer Output buffer (minimum 64 bytes)
 */
__declspec(dllimport) void GetArchitectureName(
    ArchType arch,
    char* buffer
);

// Compatibility exports (match RawrCodex.asm)
__declspec(dllimport) void* RawrDisasm_Multi_Init();
__declspec(dllimport) uint32_t RawrDisasm_Multi_Decode(
    void* ctx,
    uint64_t va,
    const uint8_t* bytes,
    DecodedInstruction* outInstr
);
__declspec(dllimport) uint32_t RawrDisasm_ARM_Decode(
    void* ctx,
    uint32_t archType,
    uint64_t va,
    const uint8_t* bytes,
    DecodedInstruction* outInstr
);
__declspec(dllimport) uint32_t RawrDisasm_MIPS_Decode(
    void* ctx,
    uint32_t archType,
    uint64_t va,
    const uint8_t* bytes,
    DecodedInstruction* outInstr
);
__declspec(dllimport) uint32_t RawrDisasm_RISCV_Decode(
    void* ctx,
    uint32_t archType,
    uint64_t va,
    const uint8_t* bytes,
    DecodedInstruction* outInstr
);

} // extern "C"

// =============================================================================
// C++ Wrapper Classes
// =============================================================================

namespace RawrCodex {

/**
 * @brief Reference decoder wrapper
 * Provides the always-correct oracle implementation
 */
class ReferenceDecoder {
public:
    ReferenceDecoder() = default;
    ~ReferenceDecoder() = default;

    /**
     * @brief Decode a single instruction
     */
    bool Decode(ArchType arch, const uint8_t* bytes, uint64_t va, DecodedInstruction& outInstr) {
        return ReferenceDecoder_DecodeInstruction(arch, bytes, va, &outInstr) != 0;
    }

    /**
     * @brief Get architecture name
     */
    static const char* GetArchName(ArchType arch) {
        static char buffer[64];
        GetArchitectureName(arch, buffer);
        return buffer;
    }
};

/**
 * @brief Differential validator
 * Compares optimized decoder output against reference
 */
class DifferentialValidator {
public:
    struct ValidationResult {
        bool match;
        const char* mismatchField;
        DecodedInstruction reference;
        DecodedInstruction test;
    };

    /**
     * @brief Validate a decoded instruction
     */
    static ValidationResult Validate(
        ArchType arch,
        const uint8_t* bytes,
        uint64_t va,
        const DecodedInstruction& testInstr
    ) {
        ValidationResult result;
        result.match = false;
        result.mismatchField = nullptr;
        
        // Get reference decode
        ReferenceDecoder decoder;
        if (!decoder.Decode(arch, bytes, va, result.reference)) {
            result.mismatchField = "reference_decode_failed";
            return result;
        }
        
        result.test = testInstr;
        
        // Compare fields
        if (result.reference.length != testInstr.length) {
            result.mismatchField = "length";
            return result;
        }
        
        if (result.reference.opcode != testInstr.opcode) {
            result.mismatchField = "opcode";
            return result;
        }
        
        if (result.reference.arch != testInstr.arch) {
            result.mismatchField = "arch";
            return result;
        }
        
        if (result.reference.instrClass != testInstr.instrClass) {
            result.mismatchField = "instrClass";
            return result;
        }
        
        if (strncmp(result.reference.mnemonic, testInstr.mnemonic, 32) != 0) {
            result.mismatchField = "mnemonic";
            return result;
        }
        
        result.match = true;
        return result;
    }
};

} // namespace RawrCodex
