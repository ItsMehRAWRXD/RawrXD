/*==========================================================================
 * x64 Assembler Validation Layer - Implementation
 * Pre-flight checks for opcode/operand compatibility
 *=========================================================================*/

#include "x64_validate.h"
#include <string.h>

// ============================================================================
// Error Messages
// ============================================================================

const char* x64_validation_error_string(x64_validation_error_t err) {
    switch (err) {
        case X64_OK: return "Success";
        case X64_ERR_INVALID_OPERAND_SIZE: return "Invalid operand size";
        case X64_ERR_INVALID_REGISTER_COMBO: return "Invalid register combination";
        case X64_ERR_INVALID_MEMORY_OPERAND: return "Invalid memory operand";
        case X64_ERR_IMMEDIATE_OUT_OF_RANGE: return "Immediate value out of range";
        case X64_ERR_ILLEGAL_LOCK_PREFIX: return "Illegal LOCK prefix";
        case X64_ERR_UNSUPPORTED_OPERAND_TYPE: return "Unsupported operand type";
        case X64_ERR_MISSING_OPERAND: return "Missing required operand";
        case X64_ERR_TOO_MANY_OPERANDS: return "Too many operands";
        case X64_ERR_INVALID_REX_PREFIX: return "Invalid REX prefix";
        case X64_ERR_UNALIGNED_MEMORY_ACCESS: return "Unaligned memory access";
        default: return "Unknown error";
    }
}

// ============================================================================
// Operand Validation
// ============================================================================

x64_validation_error_t x64_validate_operand(const x64_operand_t* op,
                                            uint32_t allowed_types,
                                            uint32_t allowed_sizes) {
    if (!op) return X64_OK;  // NULL operand is valid (optional)
    
    // Check operand type
    if (!(allowed_types & (1u << op->type))) {
        return X64_ERR_UNSUPPORTED_OPERAND_TYPE;
    }
    
    // Check operand size
    if (!(allowed_sizes & (1u << op->size))) {
        return X64_ERR_INVALID_OPERAND_SIZE;
    }
    
    // Type-specific validation
    switch (op->type) {
        case OP_IMM:
            if (!x64_validate_immediate_range(op->imm, op->size)) {
                return X64_ERR_IMMEDIATE_OUT_OF_RANGE;
            }
            break;
            
        case OP_MEM:
            return x64_validate_memory_operand(&op->mem);
            
        case OP_REG:
            // Register validation happens at combination level
            break;
            
        default:
            break;
    }
    
    return X64_OK;
}

bool x64_validate_register_combo(x64_reg_t reg1, x64_reg_t reg2) {
    // Check for valid register combinations
    // e.g., cannot mix 8-bit high registers (ah, bh, ch, dh) with REX registers
    
    // High 8-bit registers
    bool reg1_is_high = (reg1 >= 4 && reg1 <= 7);  // ah, ch, dh, bh
    bool reg2_is_rex = (reg2 >= 8);  // r8-r15
    
    if (reg1_is_high && reg2_is_rex) {
        return false;  // Cannot use ah/bh/ch/dh with r8-r15
    }
    
    return true;
}

bool x64_validate_immediate_range(int64_t value, operand_size_t size) {
    switch (size) {
        case SZ_BYTE:
            return (value >= -128 && value <= 255);
        case SZ_WORD:
            return (value >= -32768 && value <= 65535);
        case SZ_DWORD:
            return (value >= -2147483648LL && value <= 4294967295LL);
        case SZ_QWORD:
            return true;  // 64-bit can hold any value
        default:
            return false;
    }
}

x64_validation_error_t x64_validate_memory_operand(const mem_operand_t* mem) {
    if (!mem) return X64_OK;
    
    // Validate base register
    if (mem->base != X64_REG_NONE && mem->base > REG_R15) {
        return X64_ERR_INVALID_MEMORY_OPERAND;
    }
    
    // Validate index register
    if (mem->index != X64_REG_NONE && mem->index > REG_R15) {
        return X64_ERR_INVALID_MEMORY_OPERAND;
    }
    
    // Validate scale
    if (mem->scale != 0 && mem->scale != 1 && mem->scale != 2 && 
        mem->scale != 4 && mem->scale != 8) {
        return X64_ERR_INVALID_MEMORY_OPERAND;
    }
    
    // RSP cannot be used as index
    if (mem->index == REG_RSP) {
        return X64_ERR_INVALID_MEMORY_OPERAND;
    }
    
    // If both base and index are NONE, that's invalid
    if (mem->base == X64_REG_NONE && mem->index == X64_REG_NONE) {
        return X64_ERR_INVALID_MEMORY_OPERAND;
    }
    
    return X64_OK;
}

bool x64_validate_lock_prefix(x64_mnemonic_t mnem, const x64_operand_t* op1) {
    // LOCK prefix is only valid on certain instructions with memory operands
    
    // Instructions that support LOCK
    switch (mnem) {
        case MNEM_ADD:
        case MNEM_AND:
        case MNEM_DEC:
        case MNEM_INC:
        case MNEM_NEG:
        case MNEM_NOT:
        case MNEM_OR:
        case MNEM_SUB:
        case MNEM_XOR:
        case MNEM_XCHG:
            // These support LOCK, but only with memory destination
            if (op1 && op1->type == OP_MEM) {
                return true;
            }
            break;
            
        default:
            break;
    }
    
    return false;
}

// ============================================================================
// Instruction-Specific Validation
// ============================================================================

static x64_validation_error_t validate_mov(const x64_operand_t* op1, 
                                           const x64_operand_t* op2) {
    // MOV requires two operands
    if (!op1 || !op2) {
        return X64_ERR_MISSING_OPERAND;
    }
    
    // Cannot have two memory operands
    if (op1->type == OP_MEM && op2->type == OP_MEM) {
        return X64_ERR_INVALID_MEMORY_OPERAND;
    }
    
    // Cannot have two immediate operands
    if (op1->type == OP_IMM || op2->type == OP_IMM) {
        // Only destination can be immediate (which is invalid)
        if (op1->type == OP_IMM) {
            return X64_ERR_UNSUPPORTED_OPERAND_TYPE;
        }
    }
    
    // Size validation
    if (op1->size != op2->size) {
        // Special case: immediate to smaller register is OK if value fits
        if (op2->type == OP_IMM) {
            if (!x64_validate_immediate_range(op2->imm, op1->size)) {
                return X64_ERR_IMMEDIATE_OUT_OF_RANGE;
            }
        } else {
            return X64_ERR_INVALID_OPERAND_SIZE;
        }
    }
    
    return X64_OK;
}

static x64_validation_error_t validate_alu(x64_mnemonic_t mnem,
                                           const x64_operand_t* op1,
                                           const x64_operand_t* op2) {
    // ALU instructions require two operands
    if (!op1 || !op2) {
        return X64_ERR_MISSING_OPERAND;
    }
    
    // Destination cannot be immediate
    if (op1->type == OP_IMM) {
        return X64_ERR_UNSUPPORTED_OPERAND_TYPE;
    }
    
    // Cannot have two memory operands
    if (op1->type == OP_MEM && op2->type == OP_MEM) {
        return X64_ERR_INVALID_MEMORY_OPERAND;
    }
    
    // Size validation
    if (op1->size != op2->size) {
        if (op2->type == OP_IMM) {
            if (!x64_validate_immediate_range(op2->imm, op1->size)) {
                return X64_ERR_IMMEDIATE_OUT_OF_RANGE;
            }
        } else {
            return X64_ERR_INVALID_OPERAND_SIZE;
        }
    }
    
    return X64_OK;
}

static x64_validation_error_t validate_unary(x64_mnemonic_t mnem,
                                              const x64_operand_t* op1) {
    // Unary instructions require one operand
    if (!op1) {
        return X64_ERR_MISSING_OPERAND;
    }
    
    // Destination cannot be immediate
    if (op1->type == OP_IMM) {
        return X64_ERR_UNSUPPORTED_OPERAND_TYPE;
    }
    
    return X64_OK;
}

static x64_validation_error_t validate_shift(x64_mnemonic_t mnem,
                                           const x64_operand_t* op1,
                                           const x64_operand_t* op2) {
    // Shift requires two operands
    if (!op1 || !op2) {
        return X64_ERR_MISSING_OPERAND;
    }
    
    // Destination cannot be immediate
    if (op1->type == OP_IMM) {
        return X64_ERR_UNSUPPORTED_OPERAND_TYPE;
    }
    
    // Second operand must be immediate or CL
    if (op2->type != OP_IMM && 
        !(op2->type == OP_REG && op2->reg == REG_RCX)) {
        return X64_ERR_UNSUPPORTED_OPERAND_TYPE;
    }
    
    // If immediate, must be byte size (0-63 for shifts)
    if (op2->type == OP_IMM) {
        if (op2->imm < 0 || op2->imm > 63) {
            return X64_ERR_IMMEDIATE_OUT_OF_RANGE;
        }
    }
    
    return X64_OK;
}

static x64_validation_error_t validate_push_pop(const x64_operand_t* op1,
                                                bool is_push) {
    if (!op1) {
        return X64_ERR_MISSING_OPERAND;
    }
    
    // PUSH/POP cannot use immediate (except PUSH imm32 in x64)
    if (op1->type == OP_IMM) {
        if (!is_push || op1->size != SZ_DWORD) {
            return X64_ERR_UNSUPPORTED_OPERAND_TYPE;
        }
    }
    
    return X64_OK;
}

// ============================================================================
// Main Validation Entry Point
// ============================================================================

x64_validation_error_t x64_validate_operands(x64_mnemonic_t mnem, 
                                               const x64_operand_t* op1, 
                                               const x64_operand_t* op2) {
    // Route to instruction-specific validator
    switch (mnem) {
        case MNEM_MOV:
        case MNEM_MOVZX:
        case MNEM_MOVSX:
            return validate_mov(op1, op2);
            
        case MNEM_ADD:
        case MNEM_SUB:
        case MNEM_AND:
        case MNEM_OR:
        case MNEM_XOR:
        case MNEM_CMP:
            return validate_alu(mnem, op1, op2);
            
        case MNEM_INC:
        case MNEM_DEC:
        case MNEM_NEG:
        case MNEM_NOT:
            return validate_unary(mnem, op1);
            
        case MNEM_SHL:
        case MNEM_SHR:
        case MNEM_SAR:
        case MNEM_ROL:
        case MNEM_ROR:
        case MNEM_RCL:
        case MNEM_RCR:
            return validate_shift(mnem, op1, op2);
            
        case MNEM_PUSH:
            return validate_push_pop(op1, true);
            
        case MNEM_POP:
            return validate_push_pop(op1, false);
            
        case MNEM_MUL:
        case MNEM_DIV:
        case MNEM_IDIV:
            // These implicitly use RAX:RDX
            if (!op1 || op1->type == OP_IMM) {
                return X64_ERR_UNSUPPORTED_OPERAND_TYPE;
            }
            return X64_OK;
            
        case MNEM_IMUL:
            // IMUL has multiple forms
            if (!op1) {
                return X64_ERR_MISSING_OPERAND;
            }
            if (op1->type == OP_IMM) {
                return X64_ERR_UNSUPPORTED_OPERAND_TYPE;
            }
            return X64_OK;
            
        case MNEM_LEA:
            // LEA requires memory source
            if (!op1 || !op2) {
                return X64_ERR_MISSING_OPERAND;
            }
            if (op2->type != OP_MEM) {
                return X64_ERR_INVALID_MEMORY_OPERAND;
            }
            if (op1->type != OP_REG) {
                return X64_ERR_UNSUPPORTED_OPERAND_TYPE;
            }
            return X64_OK;
            
        case MNEM_CALL:
        case MNEM_JMP:
            // CALL/JMP require register or memory
            if (!op1) {
                return X64_ERR_MISSING_OPERAND;
            }
            if (op1->type != OP_REG && op1->type != OP_MEM) {
                return X64_ERR_UNSUPPORTED_OPERAND_TYPE;
            }
            return X64_OK;
            
        case MNEM_XCHG:
            // XCHG cannot have memory/memory
            if (!op1 || !op2) {
                return X64_ERR_MISSING_OPERAND;
            }
            if (op1->type == OP_MEM && op2->type == OP_MEM) {
                return X64_ERR_INVALID_MEMORY_OPERAND;
            }
            return X64_OK;
            
        default:
            // For unvalidated instructions, do basic checks
            if (op1 && op1->type == OP_IMM) {
                return X64_ERR_UNSUPPORTED_OPERAND_TYPE;
            }
            return X64_OK;
    }
}

// ============================================================================
// Safe Encoding API
// ============================================================================

x64_encoded_t x64_encode_safe(x64_mnemonic_t mnem, 
                               const x64_operand_t* op1, 
                               const x64_operand_t* op2,
                               x64_validation_error_t* out_error) {
    x64_encoded_t result = {0};
    
    // Validate first
    x64_validation_error_t err = x64_validate_operands(mnem, op1, op2);
    if (err != X64_OK) {
        if (out_error) *out_error = err;
        return result;  // len = 0 indicates failure
    }
    
    // Call the actual encoder
    result = x64_encode(mnem, op1, op2);
    
    if (out_error) {
        *out_error = (result.len > 0) ? X64_OK : X64_ERR_UNSUPPORTED_OPERAND_TYPE;
    }
    
    return result;
}
