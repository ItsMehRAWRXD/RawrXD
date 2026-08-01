/*==========================================================================
 * JIT Execution Tests - Phase 1: Runtime Execution Pipeline
 * Validates that encoded instructions actually execute correctly
 *=========================================================================*/

#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>

extern "C" {
#include "x64_encoder.h"
#include "jit_harness.h"
}

// ============================================================================
// Test Result Tracking
// ============================================================================

struct JITTestResult {
    std::string name;
    std::string description;
    bool passed;
    uint64_t expected;
    uint64_t actual;
};

static std::vector<JITTestResult> g_jit_results;
static int g_jit_passed = 0, g_jit_failed = 0;

void record_jit_result(const char* name, const char* desc, bool passed, 
                       uint64_t expected, uint64_t actual) {
    g_jit_results.push_back({name, desc, passed, expected, actual});
    if (passed) g_jit_passed++; else g_jit_failed++;
}

// ============================================================================
// JIT Test Functions
// ============================================================================

bool test_mov_imm_execution() {
    printf("\n=== JIT Test: MOV Immediate Execution ===\n");
    
    jit_context_t ctx = {0};
    if (!jit_init(&ctx, 4096)) {
        printf("  FAILED: Could not initialize JIT context\n");
        return false;
    }
    
    bool all_passed = true;
    
    // Test 1: mov rax, 42
    {
        jit_emit_return_const(&ctx, 42);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == 42);
        record_jit_result("MOV_RAX_42", "mov rax, 42; ret", pass, 42, result);
        printf("  mov rax, 42: %s (got %llu)\n", pass ? "PASS" : "FAIL", (unsigned long long)result);
        all_passed &= pass;
    }
    
    // Test 2: mov rax, 0xDEADBEEF
    {
        jit_emit_return_const(&ctx, 0xDEADBEEF);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == 0xDEADBEEF);
        record_jit_result("MOV_RAX_DEADBEEF", "mov rax, 0xDEADBEEF; ret", pass, 0xDEADBEEF, result);
        printf("  mov rax, 0xDEADBEEF: %s (got 0x%08X)\n", pass ? "PASS" : "FAIL", (unsigned int)result);
        all_passed &= pass;
    }
    
    // Test 3: mov rax, -1 (sign extension test)
    {
        jit_emit_return_const(&ctx, (uint64_t)-1);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == (uint64_t)-1);
        record_jit_result("MOV_RAX_NEG1", "mov rax, -1; ret", pass, (uint64_t)-1, result);
        printf("  mov rax, -1: %s (got 0x%016llX)\n", pass ? "PASS" : "FAIL", (unsigned long long)result);
        all_passed &= pass;
    }
    
    jit_cleanup(&ctx);
    return all_passed;
}

bool test_alu_execution() {
    printf("\n=== JIT Test: ALU Operations Execution ===\n");
    
    jit_context_t ctx = {0};
    if (!jit_init(&ctx, 4096)) {
        printf("  FAILED: Could not initialize JIT context\n");
        return false;
    }
    
    bool all_passed = true;
    
    // Test ADD: 10 + 32 = 42
    {
        jit_emit_add(&ctx, 10, 32);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == 42);
        record_jit_result("ADD_10_32", "mov rax, 10; add rax, 32; ret", pass, 42, result);
        printf("  add rax, 32 (10+32): %s (got %llu)\n", pass ? "PASS" : "FAIL", (unsigned long long)result);
        all_passed &= pass;
    }
    
    // Test SUB: 100 - 58 = 42
    {
        uint8_t code[32];
        size_t offset = 0;
        
        // mov rax, 100
        x64_operand_t dst = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
        x64_operand_t src = {.type = OP_IMM, .size = SZ_QWORD, .imm = 100};
        x64_encoded_t enc = x64_encode(MNEM_MOV, &dst, &src);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // sub rax, 58
        src.imm = 58;
        enc = x64_encode(MNEM_SUB, &dst, &src);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // ret
        code[offset++] = 0xC3;
        
        jit_load_code(&ctx, code, offset, 0);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == 42);
        record_jit_result("SUB_100_58", "mov rax, 100; sub rax, 58; ret", pass, 42, result);
        printf("  sub rax, 58 (100-58): %s (got %llu)\n", pass ? "PASS" : "FAIL", (unsigned long long)result);
        all_passed &= pass;
    }
    
    // Test AND: 0xFF & 0x0F = 0x0F
    {
        uint8_t code[32];
        size_t offset = 0;
        
        x64_operand_t dst = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
        x64_operand_t src = {.type = OP_IMM, .size = SZ_QWORD, .imm = 0xFF};
        x64_encoded_t enc = x64_encode(MNEM_MOV, &dst, &src);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        src.imm = 0x0F;
        enc = x64_encode(MNEM_AND, &dst, &src);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        code[offset++] = 0xC3;
        
        jit_load_code(&ctx, code, offset, 0);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == 0x0F);
        record_jit_result("AND_FF_0F", "mov rax, 0xFF; and rax, 0x0F; ret", pass, 0x0F, result);
        printf("  and rax, 0x0F (0xFF&0x0F): %s (got 0x%02X)\n", pass ? "PASS" : "FAIL", (unsigned int)result);
        all_passed &= pass;
    }
    
    // Test XOR: 0xFF ^ 0xFF = 0
    {
        uint8_t code[32];
        size_t offset = 0;
        
        x64_operand_t dst = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
        x64_operand_t src = {.type = OP_IMM, .size = SZ_QWORD, .imm = 0xFF};
        x64_encoded_t enc = x64_encode(MNEM_MOV, &dst, &src);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        src.type = OP_REG; src.reg = REG_RAX;
        enc = x64_encode(MNEM_XOR, &dst, &src);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        code[offset++] = 0xC3;
        
        jit_load_code(&ctx, code, offset, 0);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == 0);
        record_jit_result("XOR_RAX_RAX", "mov rax, 0xFF; xor rax, rax; ret", pass, 0, result);
        printf("  xor rax, rax: %s (got %llu)\n", pass ? "PASS" : "FAIL", (unsigned long long)result);
        all_passed &= pass;
    }
    
    jit_cleanup(&ctx);
    return all_passed;
}

bool test_register_operations() {
    printf("\n=== JIT Test: Register Operations ===\n");
    
    jit_context_t ctx = {0};
    if (!jit_init(&ctx, 4096)) {
        printf("  FAILED: Could not initialize JIT context\n");
        return false;
    }
    
    bool all_passed = true;
    
    // Test: mov rax, 5; mov rbx, 10; add rax, rbx; ret
    {
        uint8_t code[64];
        size_t offset = 0;
        
        // mov rax, 5
        x64_operand_t rax = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
        x64_operand_t imm = {.type = OP_IMM, .size = SZ_QWORD, .imm = 5};
        x64_encoded_t enc = x64_encode(MNEM_MOV, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // mov rbx, 10
        x64_operand_t rbx = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RBX};
        imm.imm = 10;
        enc = x64_encode(MNEM_MOV, &rbx, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // add rax, rbx
        enc = x64_encode(MNEM_ADD, &rax, &rbx);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // ret
        code[offset++] = 0xC3;
        
        jit_load_code(&ctx, code, offset, 0);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == 15);
        record_jit_result("REG_MOV_ADD", "mov rax,5; mov rbx,10; add rax,rbx; ret", pass, 15, result);
        printf("  reg-to-reg add: %s (got %llu, expected 15)\n", pass ? "PASS" : "FAIL", (unsigned long long)result);
        all_passed &= pass;
    }
    
    // Test: mov rax, 0x1234; xchg rax, rbx; ret (verify rax gets rbx's old value)
    // Actually let's just verify xchg works by swapping with immediate-loaded reg
    {
        uint8_t code[64];
        size_t offset = 0;
        
        // mov rax, 0xAAAA
        x64_operand_t rax = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
        x64_operand_t imm = {.type = OP_IMM, .size = SZ_QWORD, .imm = 0xAAAA};
        x64_encoded_t enc = x64_encode(MNEM_MOV, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // mov rbx, 0xBBBB
        x64_operand_t rbx = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RBX};
        imm.imm = 0xBBBB;
        enc = x64_encode(MNEM_MOV, &rbx, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // xchg rax, rbx
        enc = x64_encode(MNEM_XCHG, &rax, &rbx);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // ret (rax should now be 0xBBBB)
        code[offset++] = 0xC3;
        
        jit_load_code(&ctx, code, offset, 0);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == 0xBBBB);
        record_jit_result("XCHG_RAX_RBX", "mov rax,0xAAAA; mov rbx,0xBBBB; xchg rax,rbx; ret", pass, 0xBBBB, result);
        printf("  xchg rax, rbx: %s (got 0x%04X, expected 0xBBBB)\n", pass ? "PASS" : "FAIL", (unsigned int)result);
        all_passed &= pass;
    }
    
    jit_cleanup(&ctx);
    return all_passed;
}

bool test_stack_operations() {
    printf("\n=== JIT Test: Stack Operations ===\n");
    
    jit_context_t ctx = {0};
    if (!jit_init(&ctx, 4096)) {
        printf("  FAILED: Could not initialize JIT context\n");
        return false;
    }
    
    bool all_passed = true;
    
    // Test: push 42; pop rax; ret
    {
        uint8_t code[32];
        size_t offset = 0;
        
        // push 42 (immediate)
        x64_operand_t imm = {.type = OP_IMM, .size = SZ_QWORD, .imm = 42};
        x64_operand_t tmp = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
        
        // mov rax, 42; push rax
        x64_encoded_t enc = x64_encode(MNEM_MOV, &tmp, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        enc = x64_encode(MNEM_PUSH, &tmp, NULL);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // pop rax
        enc = x64_encode(MNEM_POP, &tmp, NULL);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // ret
        code[offset++] = 0xC3;
        
        jit_load_code(&ctx, code, offset, 0);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == 42);
        record_jit_result("PUSH_POP", "mov rax,42; push rax; pop rax; ret", pass, 42, result);
        printf("  push/pop: %s (got %llu)\n", pass ? "PASS" : "FAIL", (unsigned long long)result);
        all_passed &= pass;
    }
    
    jit_cleanup(&ctx);
    return all_passed;
}

bool test_control_flow_loops() {
    printf("\n=== JIT Test: Control Flow ===\n");
    
    jit_context_t ctx = {0};
    if (!jit_init(&ctx, 4096)) {
        printf("  FAILED: Could not initialize JIT context\n");
        return false;
    }
    
    bool all_passed = true;
    
    // Test: Simple forward jump (no loop)
    // mov rax, 1
    // jmp skip
    // mov rax, 999  ; should be skipped
    // skip:
    // mov rax, 42
    // ret
    {
        uint8_t code[64];
        size_t offset = 0;
        
        // mov rax, 1
        x64_operand_t rax = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
        x64_operand_t imm = {.type = OP_IMM, .size = SZ_QWORD, .imm = 1};
        x64_encoded_t enc = x64_encode(MNEM_MOV, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // jmp skip (placeholder)
        code[offset++] = 0xEB;  // JMP rel8
        size_t jmp_offset = offset;
        code[offset++] = 0x00;  // Will patch
        
        // mov rax, 999 (should be skipped)
        imm.imm = 999;
        enc = x64_encode(MNEM_MOV, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // skip label:
        size_t skip_label = offset;
        
        // mov rax, 42
        imm.imm = 42;
        enc = x64_encode(MNEM_MOV, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // ret
        code[offset++] = 0xC3;
        
        // Patch jmp: jump from after jmp to skip_label
        int8_t rel = (int8_t)(skip_label - (jmp_offset + 1));
        code[jmp_offset] = (uint8_t)rel;
        
        jit_load_code(&ctx, code, offset, 0);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == 42);
        record_jit_result("JMP_FORWARD", "Forward jmp (skip)", pass, 42, result);
        printf("  Forward jmp: %s (got %llu, expected 42)\n", pass ? "PASS" : "FAIL", (unsigned long long)result);
        all_passed &= pass;
    }
    
    // Test: Conditional jump (test ZF flag)
    // mov rax, 5
    // cmp rax, 5
    // je equal
    // mov rax, 999  ; should be skipped
    // equal:
    // mov rax, 42
    // ret
    {
        uint8_t code[128];
        size_t offset = 0;
        
        // mov rax, 5
        x64_operand_t rax = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
        x64_operand_t imm = {.type = OP_IMM, .size = SZ_QWORD, .imm = 5};
        x64_encoded_t enc = x64_encode(MNEM_MOV, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // cmp rax, 5
        enc = x64_encode(MNEM_CMP, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // je equal (0x74 rel8)
        code[offset++] = 0x74;  // JE rel8
        size_t je_offset = offset;
        code[offset++] = 0x00;  // Will patch
        
        // mov rax, 999 (should be skipped)
        imm.imm = 999;
        enc = x64_encode(MNEM_MOV, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // equal label:
        size_t equal_label = offset;
        
        // mov rax, 42
        imm.imm = 42;
        enc = x64_encode(MNEM_MOV, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // ret
        code[offset++] = 0xC3;
        
        // Patch je: jump to equal_label
        int8_t rel = (int8_t)(equal_label - (je_offset + 1));
        code[je_offset] = (uint8_t)rel;
        
        jit_load_code(&ctx, code, offset, 0);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == 42);
        record_jit_result("JE_EQUAL", "Conditional je (equal)", pass, 42, result);
        printf("  Conditional je: %s (got %llu, expected 42)\n", pass ? "PASS" : "FAIL", (unsigned long long)result);
        all_passed &= pass;
    }
    
    jit_cleanup(&ctx);
    return all_passed;
}

bool test_function_calls() {
    printf("\n=== JIT Test: Function Calls ===\n");
    
    jit_context_t ctx = {0};
    if (!jit_init(&ctx, 4096)) {
        printf("  FAILED: Could not initialize JIT context\n");
        return false;
    }
    
    bool all_passed = true;
    
    // Test: Simple call/ret with stack frame
    // Main: mov rax, 10; call double_it; ret
    // double_it: shl rax, 1; ret
    {
        uint8_t code[128];
        size_t offset = 0;
        
        // Main entry:
        // mov rax, 10
        x64_operand_t rax = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
        x64_operand_t imm = {.type = OP_IMM, .size = SZ_QWORD, .imm = 10};
        x64_encoded_t enc = x64_encode(MNEM_MOV, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // call double_it (relative offset placeholder)
        code[offset++] = 0xE8;  // CALL rel32
        size_t call_offset = offset;
        code[offset++] = 0x00;  // Will patch
        code[offset++] = 0x00;
        code[offset++] = 0x00;
        code[offset++] = 0x00;
        
        // ret
        code[offset++] = 0xC3;
        
        // double_it function:
        size_t func_start = offset;
        
        // shl rax, 1
        imm.imm = 1;
        enc = x64_encode(MNEM_SHL, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // ret
        code[offset++] = 0xC3;
        
        // Patch the call offset
        int32_t rel = (int32_t)(func_start - (call_offset + 4));
        memcpy(code + call_offset, &rel, 4);
        
        jit_load_code(&ctx, code, offset, 0);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == 20);  // 10 * 2 = 20
        record_jit_result("CALL_DOUBLE_IT", "call double_it (shl rax,1)", pass, 20, result);
        printf("  Simple call/ret: %s (got %llu, expected 20)\n", pass ? "PASS" : "FAIL", (unsigned long long)result);
        all_passed &= pass;
    }
    
    // Test: Nested calls (fibonacci-like)
    // Main: mov rax, 5; call sum_recursive; ret
    // sum_recursive: cmp rax, 1; jle base; push rax; dec rax; call sum_recursive; pop rbx; add rax, rbx; ret
    // base: mov rax, 1; ret
    {
        uint8_t code[256];
        size_t offset = 0;
        
        // Main: mov rax, 5
        x64_operand_t rax = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
        x64_operand_t imm = {.type = OP_IMM, .size = SZ_QWORD, .imm = 5};
        x64_encoded_t enc = x64_encode(MNEM_MOV, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // call sum_recursive
        code[offset++] = 0xE8;
        size_t call_offset = offset;
        offset += 4;  // Space for rel32
        
        // ret
        code[offset++] = 0xC3;
        
        // sum_recursive function:
        size_t func_start = offset;
        
        // cmp rax, 1
        imm.imm = 1;
        x64_operand_t tmp = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
        enc = x64_encode(MNEM_CMP, &tmp, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // jle base (0x7E + rel8)
        code[offset++] = 0x7E;  // JLE rel8
        size_t jle_offset = offset;
        offset++;  // Space for rel8
        
        // push rax
        enc = x64_encode(MNEM_PUSH, &rax, NULL);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // dec rax
        enc = x64_encode(MNEM_DEC, &rax, NULL);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // call sum_recursive (recursive)
        code[offset++] = 0xE8;
        int32_t rel = (int32_t)(func_start - (offset + 4));
        memcpy(code + offset, &rel, 4); offset += 4;
        
        // pop rbx
        x64_operand_t rbx = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RBX};
        enc = x64_encode(MNEM_POP, &rbx, NULL);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // add rax, rbx
        enc = x64_encode(MNEM_ADD, &rax, &rbx);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // ret
        code[offset++] = 0xC3;
        
        // base label:
        size_t base_label = offset;
        
        // mov rax, 1
        imm.imm = 1;
        enc = x64_encode(MNEM_MOV, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // ret
        code[offset++] = 0xC3;
        
        // Patch jle offset
        int8_t jle_rel = (int8_t)(base_label - (jle_offset + 1));
        code[jle_offset] = jle_rel;
        
        // Patch initial call offset
        rel = (int32_t)(func_start - (call_offset + 4));
        memcpy(code + call_offset, &rel, 4);
        
        jit_load_code(&ctx, code, offset, 0);
        uint64_t result = jit_execute(&ctx, 0);
        // sum(5) = 5+4+3+2+1 = 15
        bool pass = (result == 15);
        record_jit_result("SUM_RECURSIVE", "Recursive sum(5)", pass, 15, result);
        printf("  Recursive sum(5): %s (got %llu, expected 15)\n", pass ? "PASS" : "FAIL", (unsigned long long)result);
        all_passed &= pass;
    }
    
    jit_cleanup(&ctx);
    return all_passed;
}

bool test_memory_operations() {
    printf("\n=== JIT Test: Memory Operations ===\n");
    
    jit_context_t ctx = {0};
    if (!jit_init(&ctx, 4096)) {
        printf("  FAILED: Could not initialize JIT context\n");
        return false;
    }
    
    bool all_passed = true;
    
    // Test: Store and load from stack memory
    // mov rax, 0x12345678
    // push rax
    // pop rbx
    // mov rax, rbx
    // ret
    {
        uint8_t code[64];
        size_t offset = 0;
        
        // mov rax, 0x12345678
        x64_operand_t rax = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
        x64_operand_t imm = {.type = OP_IMM, .size = SZ_QWORD, .imm = 0x12345678};
        x64_encoded_t enc = x64_encode(MNEM_MOV, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // push rax (store to stack)
        enc = x64_encode(MNEM_PUSH, &rax, NULL);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // pop rbx (load from stack)
        x64_operand_t rbx = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RBX};
        enc = x64_encode(MNEM_POP, &rbx, NULL);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // mov rax, rbx
        enc = x64_encode(MNEM_MOV, &rax, &rbx);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // ret
        code[offset++] = 0xC3;
        
        jit_load_code(&ctx, code, offset, 0);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == 0x12345678);
        record_jit_result("STACK_MEM", "Stack push/pop memory", pass, 0x12345678, result);
        printf("  Stack memory: %s (got 0x%08X, expected 0x12345678)\n", pass ? "PASS" : "FAIL", (unsigned int)result);
        all_passed &= pass;
    }
    
    // Test: Complex ALU chain
    // mov rax, 1
    // add rax, 2
    // shl rax, 2
    // add rax, 3
    // Result: ((1+2) << 2) + 3 = (3 << 2) + 3 = 12 + 3 = 15
    {
        uint8_t code[64];
        size_t offset = 0;
        
        // mov rax, 1
        x64_operand_t rax = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
        x64_operand_t imm = {.type = OP_IMM, .size = SZ_QWORD, .imm = 1};
        x64_encoded_t enc = x64_encode(MNEM_MOV, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // add rax, 2
        imm.imm = 2;
        enc = x64_encode(MNEM_ADD, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // shl rax, 2
        imm.imm = 2;
        enc = x64_encode(MNEM_SHL, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // add rax, 3
        imm.imm = 3;
        enc = x64_encode(MNEM_ADD, &rax, &imm);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // ret
        code[offset++] = 0xC3;
        
        jit_load_code(&ctx, code, offset, 0);
        uint64_t result = jit_execute(&ctx, 0);
        bool pass = (result == 15);
        record_jit_result("ALU_CHAIN", "Complex ALU chain", pass, 15, result);
        printf("  ALU chain: %s (got %llu, expected 15)\n", pass ? "PASS" : "FAIL", (unsigned long long)result);
        all_passed &= pass;
    }
    
    jit_cleanup(&ctx);
    return all_passed;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("==========================================================================\n");
    printf("x64 Assembler - JIT Execution Tests (Phase 1: Runtime Execution)\n");
    printf("==========================================================================\n");
    
    bool all_passed = true;
    
    all_passed &= test_mov_imm_execution();
    all_passed &= test_alu_execution();
    all_passed &= test_register_operations();
    all_passed &= test_stack_operations();
    all_passed &= test_control_flow_loops();
    all_passed &= test_memory_operations();
    
    printf("\n==========================================================================\n");
    printf("JIT EXECUTION SUMMARY\n");
    printf("==========================================================================\n");
    printf("Total JIT Tests: %zu\n", g_jit_results.size());
    printf("  PASSED: %d\n", g_jit_passed);
    printf("  FAILED: %d\n", g_jit_failed);
    printf("\nExecution Verification: %s\n", all_passed ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    printf("==========================================================================\n");
    
    return all_passed ? 0 : 1;
}
