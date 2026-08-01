/*==========================================================================
 * JIT Execution Harness - Implementation
 * Windows implementation using VirtualAlloc
 *=========================================================================*/

#include "jit_harness.h"
#include "x64_encoder.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

// ============================================================================
// JIT Context Management
// ============================================================================

bool jit_init(jit_context_t* ctx, size_t size) {
    if (!ctx || size == 0) return false;
    
    // Round up to page size (4096 bytes minimum)
    size_t alloc_size = (size + 4095) & ~4095;
    
    // Allocate RWX memory for simplicity in testing
    // In production, use RW first then VirtualProtect to RX
    ctx->code_buffer = VirtualAlloc(
        NULL,                    // Let system choose address
        alloc_size,              // Size to allocate
        MEM_COMMIT | MEM_RESERVE, // Reserve and commit
        PAGE_EXECUTE_READWRITE   // RWX for JIT
    );
    
    if (!ctx->code_buffer) {
        fprintf(stderr, "[JIT] VirtualAlloc failed: %lu\n", GetLastError());
        return false;
    }
    
    ctx->buffer_size = alloc_size;
    ctx->is_executable = true;
    
    // Zero the buffer
    memset(ctx->code_buffer, 0, alloc_size);
    
    return true;
}

bool jit_load_code(jit_context_t* ctx, const uint8_t* code, size_t code_len, size_t offset) {
    if (!ctx || !ctx->code_buffer || !code || code_len == 0) return false;
    
    // Check bounds
    if (offset + code_len > ctx->buffer_size) {
        fprintf(stderr, "[JIT] Code too large for buffer\n");
        return false;
    }
    
    // Copy code to executable buffer
    memcpy((uint8_t*)ctx->code_buffer + offset, code, code_len);
    
    // Flush instruction cache to ensure CPU sees the new code
    FlushInstructionCache(GetCurrentProcess(), 
                          (uint8_t*)ctx->code_buffer + offset, 
                          code_len);
    
    return true;
}

uint64_t jit_execute(jit_context_t* ctx, size_t entry_offset) {
    if (!ctx || !ctx->code_buffer || !ctx->is_executable) {
        fprintf(stderr, "[JIT] Context not initialized\n");
        return 0;
    }
    
    if (entry_offset >= ctx->buffer_size) {
        fprintf(stderr, "[JIT] Entry offset out of bounds\n");
        return 0;
    }
    
    // Cast buffer to function pointer and call
    jit_func_t func = (jit_func_t)((uint8_t*)ctx->code_buffer + entry_offset);
    
    // Execute the JIT code
    uint64_t result = func();
    
    return result;
}

void jit_cleanup(jit_context_t* ctx) {
    if (!ctx || !ctx->code_buffer) return;
    
    VirtualFree(ctx->code_buffer, 0, MEM_RELEASE);
    ctx->code_buffer = NULL;
    ctx->buffer_size = 0;
    ctx->is_executable = false;
}

// ============================================================================
// Convenience Functions
// ============================================================================

uint64_t jit_execute_once(const uint8_t* code, size_t code_len) {
    jit_context_t ctx = {0};
    
    if (!jit_init(&ctx, code_len + 16)) {  // Extra space for safety
        return 0;
    }
    
    if (!jit_load_code(&ctx, code, code_len, 0)) {
        jit_cleanup(&ctx);
        return 0;
    }
    
    uint64_t result = jit_execute(&ctx, 0);
    jit_cleanup(&ctx);
    
    return result;
}

// ============================================================================
// Test Integration Helpers
// ============================================================================

bool jit_verify_encoding(x64_encoded_t encoded, uint64_t expected_rax, const char* test_name) {
    // Append RET instruction (0xC3) to make the code return
    uint8_t code[32];
    size_t len = encoded.len;
    
    if (len >= sizeof(code) - 1) {
        fprintf(stderr, "[JIT] %s: Code too long\n", test_name);
        return false;
    }
    
    memcpy(code, encoded.bytes, len);
    code[len] = 0xC3;  // RET instruction
    
    uint64_t result = jit_execute_once(code, len + 1);
    
    if (result != expected_rax) {
        fprintf(stderr, "[JIT] %s: FAILED - expected 0x%016llX, got 0x%016llX\n", 
                test_name, (unsigned long long)expected_rax, (unsigned long long)result);
        return false;
    }
    
    printf("[JIT] %s: PASSED (RAX = 0x%016llX)\n", test_name, (unsigned long long)result);
    return true;
}

bool jit_emit_return_const(jit_context_t* ctx, uint64_t value) {
    if (!ctx || !ctx->code_buffer) return false;
    
    // Build: mov rax, imm64; ret
    x64_operand_t dst = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
    x64_operand_t src = {.type = OP_IMM, .size = SZ_QWORD, .imm = (int64_t)value};
    
    x64_encoded_t mov_enc = x64_encode(MNEM_MOV, &dst, &src);
    if (mov_enc.len == 0) return false;
    
    // Copy MOV instruction
    if (!jit_load_code(ctx, mov_enc.bytes, mov_enc.len, 0)) return false;
    
    // Append RET
    uint8_t ret = 0xC3;
    if (!jit_load_code(ctx, &ret, 1, mov_enc.len)) return false;
    
    return true;
}

bool jit_emit_add(jit_context_t* ctx, uint64_t a, uint64_t b) {
    if (!ctx || !ctx->code_buffer) return false;
    
    size_t offset = 0;
    uint8_t code[32];
    
    // Build: mov rax, a; add rax, b; ret
    
    // mov rax, a
    x64_operand_t dst = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
    x64_operand_t src = {.type = OP_IMM, .size = SZ_QWORD, .imm = (int64_t)a};
    x64_encoded_t enc = x64_encode(MNEM_MOV, &dst, &src);
    if (enc.len == 0) return false;
    memcpy(code + offset, enc.bytes, enc.len);
    offset += enc.len;
    
    // add rax, b
    src.imm = (int64_t)b;
    enc = x64_encode(MNEM_ADD, &dst, &src);
    if (enc.len == 0) return false;
    memcpy(code + offset, enc.bytes, enc.len);
    offset += enc.len;
    
    // ret
    code[offset++] = 0xC3;
    
    return jit_load_code(ctx, code, offset, 0);
}
