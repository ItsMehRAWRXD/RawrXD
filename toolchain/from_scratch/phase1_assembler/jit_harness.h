/*==========================================================================
 * JIT Execution Harness
 * Executes assembled x64 code in dynamically allocated memory
 * Phase 1: Runtime Execution Pipeline for RawrXD
 *=========================================================================*/

#ifndef JIT_HARNESS_H
#define JIT_HARNESS_H

#include <stdint.h>
#include <stdbool.h>
#include "x64_encoder.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// JIT Execution Context
// ============================================================================

typedef struct {
    void* code_buffer;      // Pointer to executable memory
    size_t buffer_size;     // Size of allocated buffer
    bool is_executable;     // Whether memory has execute permissions
} jit_context_t;

// Function pointer type for JIT code (returns 64-bit value)
typedef uint64_t (*jit_func_t)(void);

// ============================================================================
// API Functions
// ============================================================================

/**
 * Initialize JIT context with executable memory
 * @param ctx Pointer to JIT context to initialize
 * @param size Size of executable buffer to allocate (minimum 4096 bytes)
 * @return true on success, false on failure
 */
bool jit_init(jit_context_t* ctx, size_t size);

/**
 * Copy assembled code into JIT buffer and prepare for execution
 * @param ctx Initialized JIT context
 * @param code Pointer to assembled bytes
 * @param code_len Length of assembled code
 * @param offset Offset into buffer where code should be written
 * @return true on success, false on failure
 */
bool jit_load_code(jit_context_t* ctx, const uint8_t* code, size_t code_len, size_t offset);

/**
 * Execute JIT code and return result
 * @param ctx Initialized JIT context with loaded code
 * @param entry_offset Offset in buffer where execution should start
 * @return 64-bit value from RAX register after execution
 */
uint64_t jit_execute(jit_context_t* ctx, size_t entry_offset);

/**
 * Cleanup JIT context and free executable memory
 * @param ctx JIT context to cleanup
 */
void jit_cleanup(jit_context_t* ctx);

/**
 * Convenience: Execute assembled code in one shot
 * Allocates memory, copies code, executes, and cleans up
 * @param code Pointer to assembled bytes
 * @param code_len Length of assembled code
 * @return 64-bit value from RAX register, or 0 on failure
 */
uint64_t jit_execute_once(const uint8_t* code, size_t code_len);

// ============================================================================
// Test Integration Helpers
// ============================================================================

/**
 * Verify that encoded instruction produces expected result when executed
 * @param encoded Encoded instruction bytes
 * @param expected_rax Expected value in RAX after execution
 * @param test_name Name of test for error reporting
 * @return true if execution result matches expected, false otherwise
 */
bool jit_verify_encoding(x64_encoded_t encoded, uint64_t expected_rax, const char* test_name);

/**
 * Create a simple function that returns a constant value
 * Generates: mov rax, imm64; ret
 * @param ctx JIT context
 * @param value Value to return
 * @return true on success
 */
bool jit_emit_return_const(jit_context_t* ctx, uint64_t value);

/**
 * Create a simple function that adds two values
 * Generates: mov rax, a; add rax, b; ret
 * @param ctx JIT context
 * @param a First operand
 * @param b Second operand
 * @return true on success
 */
bool jit_emit_add(jit_context_t* ctx, uint64_t a, uint64_t b);

#ifdef __cplusplus
}
#endif

#endif // JIT_HARNESS_H
