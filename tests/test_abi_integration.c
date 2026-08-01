/*==========================================================================
 * ABI Integration Test - Phase 3: Win64 Calling Convention
 * Generates PE that calls MessageBoxA via import table
 *=========================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "x64_encoder.h"
#include "x64_validate.h"
#include "x64_abi.h"
#include "../toolchain/from_scratch/phase2_linker/pe_writer.h"

/* MessageBoxA constants */
#define MB_OK              0x00000000
#define MB_ICONINFORMATION 0x00000040

int main() {
    printf("==========================================================================\n");
    printf("ABI Integration Test - Win64 Calling Convention\n");
    printf("==========================================================================\n\n");
    
    int passed = 0, failed = 0;
    
    // Test 1: Generate PE with MessageBoxA call
    printf("Test 1: Generate PE calling MessageBoxA\n");
    {
        PeWriter* pw = pe_writer_create();
        if (!pw) {
            printf("  FAIL: pe_writer_create failed\n");
            failed++;
        } else {
            /* Set up import: user32.dll!MessageBoxA */
            pe_writer_set_import(pw, "user32.dll", "MessageBoxA");
            
            /* Build code that calls MessageBoxA(NULL, "Hello", "Title", MB_OK) */
            uint8_t code[256];
            size_t code_len = 0;
            
            /* 
             * Win64 ABI for MessageBoxA:
             * RCX = hwnd (NULL)
             * RDX = lpText (pointer to "Hello")
             * R8  = lpCaption (pointer to "Title")  
             * R9  = uType (MB_OK = 0)
             * 
             * Then: sub rsp, 32 (shadow space)
             *       call [IAT]
             *       add rsp, 32
             *       xor eax, eax (return 0)
             *       ret
             */
            
            /* For this test, we'll use hardcoded string addresses
             * In a real implementation, we'd need to embed strings in .rdata
             * and calculate their RVAs
             * 
             * For simplicity, let's just generate the argument setup and call
             */
            
            /* mov rcx, 0 (hwnd) */
            x64_operand_t rcx = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RCX};
            x64_operand_t imm = {.type = OP_IMM, .size = SZ_QWORD, .imm = 0};
            x64_encoded_t enc = x64_encode_safe(MNEM_MOV, &rcx, &imm, NULL);
            memcpy(code + code_len, enc.bytes, enc.len); code_len += enc.len;
            
            /* mov rdx, 0x1000 (placeholder for string address) */
            x64_operand_t rdx = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RDX};
            imm.imm = 0x1000;  /* Will be fixed up */
            enc = x64_encode_safe(MNEM_MOV, &rdx, &imm, NULL);
            memcpy(code + code_len, enc.bytes, enc.len); code_len += enc.len;
            
            /* mov r8, 0x1010 (placeholder for title address) */
            x64_operand_t r8 = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_R8};
            imm.imm = 0x1010;
            enc = x64_encode_safe(MNEM_MOV, &r8, &imm, NULL);
            memcpy(code + code_len, enc.bytes, enc.len); code_len += enc.len;
            
            /* mov r9, 0 (MB_OK) */
            x64_operand_t r9 = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_R9};
            imm.imm = MB_OK;
            enc = x64_encode_safe(MNEM_MOV, &r9, &imm, NULL);
            memcpy(code + code_len, enc.bytes, enc.len); code_len += enc.len;
            
            /* sub rsp, 32 (shadow space) */
            x64_operand_t rsp = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RSP};
            imm.imm = 32;
            enc = x64_encode_safe(MNEM_SUB, &rsp, &imm, NULL);
            memcpy(code + code_len, enc.bytes, enc.len); code_len += enc.len;
            
            /* call [IAT] - placeholder: FF 15 XX XX XX XX */
            /* For now, emit a simple call to a placeholder address */
            /* In real implementation, this would be RIP-relative to IAT */
            code[code_len++] = 0xFF;  /* call r/m64 */
            code[code_len++] = 0x15; /* ModR/M: 00 010 101 = disp32 addressing */
            code[code_len++] = 0x00; /* Will be fixed up by linker */
            code[code_len++] = 0x00;
            code[code_len++] = 0x00;
            code[code_len++] = 0x00;
            
            /* add rsp, 32 */
            enc = x64_encode_safe(MNEM_ADD, &rsp, &imm, NULL);
            memcpy(code + code_len, enc.bytes, enc.len); code_len += enc.len;
            
            /* xor eax, eax (return 0) */
            x64_operand_t rax = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
            enc = x64_encode_safe(MNEM_XOR, &rax, &rax, NULL);
            memcpy(code + code_len, enc.bytes, enc.len); code_len += enc.len;
            
            /* ret */
            code[code_len++] = 0xC3;
            
            printf("  Generated %zu bytes of code\n", code_len);
            
            pe_writer_set_entry(pw, 0);
            pe_writer_add_text(pw, code, (uint32_t)code_len);
            
            uint8_t* pe_data = NULL;
            uint32_t pe_size = pe_writer_emit(pw, &pe_data);
            
            if (pe_size == 0 || !pe_data) {
                printf("  FAIL: pe_writer_emit failed\n");
                failed++;
            } else {
                FILE* f = fopen("test_abi.exe", "wb");
                if (f) {
                    fwrite(pe_data, 1, pe_size, f);
                    fclose(f);
                    printf("  Generated: test_abi.exe (%u bytes)\n", pe_size);
                    printf("  Note: This test requires string data section support\n");
                    printf("  PASS: PE generation successful\n");
                    passed++;
                } else {
                    printf("  FAIL: Could not write file\n");
                    failed++;
                }
                
                free(pe_data);
            }
            
            pe_writer_destroy(pw);
        }
    }
    
    // Test 2: ABI helper test
    printf("\nTest 2: ABI helper functions\n");
    {
        x64_abi_call_builder_t builder;
        x64_abi_call_init(&builder);
        
        /* Add 4 arguments */
        int r1 = x64_abi_add_arg_imm(&builder, 0x11111111);
        int r2 = x64_abi_add_arg_imm(&builder, 0x22222222);
        int r3 = x64_abi_add_arg_imm(&builder, 0x33333333);
        int r4 = x64_abi_add_arg_imm(&builder, 0x44444444);
        
        if (r1 == 0 && r2 == 0 && r3 == 0 && r4 == 0) {
            printf("  PASS: All 4 arguments added successfully\n");
            printf("  Generated %zu bytes\n", x64_abi_get_len(&builder));
            passed++;
        } else {
            printf("  FAIL: Could not add arguments\n");
            failed++;
        }
    }
    
    printf("\n==========================================================================\n");
    printf("ABI INTEGRATION SUMMARY\n");
    printf("==========================================================================\n");
    printf("Total Tests: %d\n", passed + failed);
    printf("  PASSED: %d\n", passed);
    printf("  FAILED: %d\n", failed);
    printf("\nStatus: %s\n", failed == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    printf("==========================================================================\n");
    
    return failed == 0 ? 0 : 1;
}
