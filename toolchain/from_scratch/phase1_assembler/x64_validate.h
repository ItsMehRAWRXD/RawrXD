/*==========================================================================
 * x64 Assembler Validation Layer
 * Pre-flight checks for opcode/operand compatibility
 * Phase 2: Negative Testing - API Hardening
 *=========================================================================*/

#ifndef X64_VALIDATE_H
#define X64_VALIDATE_H

#include "x64_encoder.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Validation Error Codes
// ============================================================================

typedef enum {
    X64_OK = 0,                          // Success
    X64_ERR_INVALID_OPERAND_SIZE,        // Operand size mismatch
    X64_ERR_INVALID_REGISTER_COMBO,    // Invalid register combination
    X64_ERR_INVALID_MEMORY_OPERAND,    // Invalid memory addressing
    X64_ERR_IMMEDIATE_OUT_OF_RANGE,    // Immediate value too large
    X64_ERR_ILLEGAL_LOCK_PREFIX,       // LOCK prefix on non-memory op
    X64_ERR_UNSUPPORTED_OPERAND_TYPE,    // Operand type not supported
    X64_ERR_MISSING_OPERAND,           // Required operand missing
    X64_ERR_TOO_MANY_OPERANDS,         // Too many operands for instruction
    X64_ERR_INVALID_REX_PREFIX,        // REX prefix conflict
    X64_ERR_UNALIGNED_MEMORY_ACCESS,   // Unaligned memory access
} x64_validation_error_t;

// ============================================================================
// Validation Functions
// ============================================================================

/**
 * Validate operands for a given mnemonic
 * @param mnem The instruction mnemonic
 * @param op1 First operand (can be NULL)
 * @param op2 Second operand (can be NULL)
 * @return X64_OK on success, error code on failure
 */
x64_validation_error_t x64_validate_operands(x64_mnemonic_t mnem, 
                                               const x64_operand_t* op1, 
                                               const x64_operand_t* op2);

/**
 * Validate a single operand
 * @param op Operand to validate
 * @param allowed_types Bitmask of allowed operand types
 * @param allowed_sizes Bitmask of allowed operand sizes
 * @return X64_OK on success, error code on failure
 */
x64_validation_error_t x64_validate_operand(const x64_operand_t* op,
                                            uint32_t allowed_types,
                                            uint32_t allowed_sizes);

/**
 * Check if register combination is valid
 * @param reg1 First register
 * @param reg2 Second register
 * @return true if valid combination
 */
bool x64_validate_register_combo(x64_reg_t reg1, x64_reg_t reg2);

/**
 * Check if immediate value fits in given size
 * @param value The immediate value
 * @param size The target size
 * @return true if value fits
 */
bool x64_validate_immediate_range(int64_t value, operand_size_t size);

/**
 * Check if LOCK prefix is valid for instruction
 * @param mnem The instruction mnemonic
 * @param op1 First operand
 * @return true if LOCK is valid
 */
bool x64_validate_lock_prefix(x64_mnemonic_t mnem, const x64_operand_t* op1);

/**
 * Validate memory operand addressing mode
 * @param mem Memory operand
 * @return X64_OK on success, error code on failure
 */
x64_validation_error_t x64_validate_memory_operand(const mem_operand_t* mem);

/**
 * Get human-readable error message
 * @param err Error code
 * @return Error message string
 */
const char* x64_validation_error_string(x64_validation_error_t err);

// ============================================================================
// Safe Encoding API
// ============================================================================

/**
 * Safe version of x64_encode with validation
 * @param mnem The instruction mnemonic
 * @param op1 First operand (can be NULL)
 * @param op2 Second operand (can be NULL)
 * @param out_error Optional: receives error code on failure
 * @return Encoded instruction (len=0 on failure)
 */
x64_encoded_t x64_encode_safe(x64_mnemonic_t mnem, 
                               const x64_operand_t* op1, 
                               const x64_operand_t* op2,
                               x64_validation_error_t* out_error);

// ============================================================================
// Validation Bitmasks
// ============================================================================

#define X64_ALLOW_REG    (1u << OP_REG)
#define X64_ALLOW_IMM    (1u << OP_IMM)
#define X64_ALLOW_MEM    (1u << OP_MEM)
#define X64_ALLOW_LOCK   (1u << OP_LOCK)
#define X64_ALLOW_REP    (1u << OP_REP)

#define X64_ALLOW_BYTE   (1u << SZ_BYTE)
#define X64_ALLOW_WORD   (1u << SZ_WORD)
#define X64_ALLOW_DWORD  (1u << SZ_DWORD)
#define X64_ALLOW_QWORD  (1u << SZ_QWORD)

#ifdef __cplusplus
}
#endif

#endif // X64_VALIDATE_H
