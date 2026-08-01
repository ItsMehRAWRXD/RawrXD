/*==========================================================================
 * x64 Win64 ABI Support - Calling Convention Helpers
 * 
 * Implements the Microsoft x64 calling convention:
 *   - First 4 args: RCX, RDX, R8, R9 (integer/pointer)
 *   - Additional args: stack (right to left)
 *   - Shadow space: 32 bytes required before call
 *   - Stack alignment: RSP must be 16-byte aligned at call
 *   - Caller cleans up stack
 *=========================================================================*/

#ifndef X64_ABI_H
#define X64_ABI_H

#include "x64_encoder.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Shadow space size (32 bytes) ---- */
#define X64_ABI_SHADOW_SPACE 32

/* ---- Argument slot for register args ---- */
typedef enum {
    X64_ARG_RCX = 0,
    X64_ARG_RDX = 1,
    X64_ARG_R8  = 2,
    X64_ARG_R9  = 3,
    X64_ARG_STACK = 4
} x64_abi_arg_slot_t;

/* ---- ABI call builder ---- */
typedef struct {
    uint8_t code[256];
    size_t len;
    int num_reg_args;
    int num_stack_args;
    size_t stack_adjust;
} x64_abi_call_builder_t;

/**
 * Initialize ABI call builder
 */
void x64_abi_call_init(x64_abi_call_builder_t* builder);

/**
 * Add integer/pointer argument
 * Automatically assigns to RCX/RDX/R8/R9 or stack
 */
int x64_abi_add_arg_imm(x64_abi_call_builder_t* builder, uint64_t value);
int x64_abi_add_arg_reg(x64_abi_call_builder_t* builder, x64_reg_t reg);

/**
 * Generate the call instruction through IAT
 * @param import_rva RVA of the IAT slot (e.g., 0x2048 for first import)
 */
int x64_abi_emit_call(x64_abi_call_builder_t* builder, uint32_t import_rva);

/**
 * Get the generated code
 */
uint8_t* x64_abi_get_code(x64_abi_call_builder_t* builder);
size_t x64_abi_get_len(x64_abi_call_builder_t* builder);

/**
 * High-level helper: Generate complete call sequence
 * 
 * Example: x64_abi_gen_call_4imm(buf, &len, 0x2048, 
 *                                0,          // RCX = NULL (hwnd)
 *                                (uint64_t)msg, // RDX = message string
 *                                (uint64_t)title, // R8 = title string
 *                                0x40);      // R9 = MB_ICONINFORMATION
 */
int x64_abi_gen_call_4imm(uint8_t* out, size_t* len, uint32_t import_rva,
                          uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

#ifdef __cplusplus
}
#endif

#endif /* X64_ABI_H */
