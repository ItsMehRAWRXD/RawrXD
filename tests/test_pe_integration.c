/*==========================================================================
 * PE Integration Test - Phase 2B: Encoder → PE Writer Pipeline
 * Generates a standalone .exe from encoded instructions
 *=========================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "x64_encoder.h"
#include "x64_validate.h"
#include "../toolchain/from_scratch/phase2_linker/pe_writer.h"

// Simple program: mov rax, 42; ret
static uint8_t simple_program[] = {
    0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00,  // mov rax, 42
    0xC3                                         // ret
};

// Program using encoder: exit code 123
static void build_exit_code_program(uint8_t* out, size_t* len, int exit_code) {
    x64_operand_t rax = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
    x64_operand_t imm = {.type = OP_IMM, .size = SZ_QWORD, .imm = exit_code};
    
    x64_encoded_t enc = x64_encode_safe(MNEM_MOV, &rax, &imm, NULL);
    memcpy(out, enc.bytes, enc.len);
    out[enc.len] = 0xC3;  // ret
    *len = enc.len + 1;
}

int main() {
    printf("==========================================================================\n");
    printf("PE Integration Test - Encoder → PE Writer Pipeline\n");
    printf("==========================================================================\n\n");
    
    int passed = 0, failed = 0;
    
    // Test 1: Generate PE with hardcoded bytes
    printf("Test 1: Generate PE with hardcoded program (mov rax, 42; ret)\n");
    {
        PeWriter* pw = pe_writer_create();
        if (!pw) {
            printf("  FAIL: pe_writer_create failed\n");
            failed++;
        } else {
            pe_writer_set_entry(pw, 0);  // Entry at start of .text
            pe_writer_add_text(pw, simple_program, sizeof(simple_program));
            
            uint8_t* pe_data = NULL;
            uint32_t pe_size = pe_writer_emit(pw, &pe_data);
            
            if (pe_size == 0 || !pe_data) {
                printf("  FAIL: pe_writer_emit failed\n");
                failed++;
            } else {
                // Write to file
                FILE* f = fopen("test_hardcoded.exe", "wb");
                if (f) {
                    fwrite(pe_data, 1, pe_size, f);
                    fclose(f);
                    printf("  Generated: test_hardcoded.exe (%u bytes)\n", pe_size);
                    
                    // Try to execute
                    printf("  Attempting to execute...\n");
                    STARTUPINFOA si = {sizeof(si)};
                    PROCESS_INFORMATION pi = {0};
                    
                    if (CreateProcessA("test_hardcoded.exe", NULL, NULL, NULL, FALSE,
                                      0, NULL, NULL, &si, &pi)) {
                        WaitForSingleObject(pi.hProcess, INFINITE);
                        
                        DWORD exit_code;
                        if (GetExitCodeProcess(pi.hProcess, &exit_code)) {
                            if (exit_code == 42) {
                                printf("  PASS: Exit code = %lu (expected 42)\n", exit_code);
                                passed++;
                            } else {
                                printf("  FAIL: Exit code = %lu (expected 42)\n", exit_code);
                                failed++;
                            }
                        } else {
                            printf("  FAIL: Could not get exit code\n");
                            failed++;
                        }
                        
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                    } else {
                        printf("  FAIL: Could not create process (error %lu)\n", GetLastError());
                        failed++;
                    }
                } else {
                    printf("  FAIL: Could not write file\n");
                    failed++;
                }
                
                free(pe_data);
            }
            
            pe_writer_destroy(pw);
        }
    }
    
    // Test 2: Generate PE using encoder
    printf("\nTest 2: Generate PE using x64_encoder (exit code 123)\n");
    {
        uint8_t code[32];
        size_t code_len;
        build_exit_code_program(code, &code_len, 123);
        
        printf("  Encoded %zu bytes: ", code_len);
        for (size_t i = 0; i < code_len; i++) {
            printf("%02X ", code[i]);
        }
        printf("\n");
        
        PeWriter* pw = pe_writer_create();
        if (!pw) {
            printf("  FAIL: pe_writer_create failed\n");
            failed++;
        } else {
            pe_writer_set_entry(pw, 0);
            pe_writer_add_text(pw, code, (uint32_t)code_len);
            
            uint8_t* pe_data = NULL;
            uint32_t pe_size = pe_writer_emit(pw, &pe_data);
            
            if (pe_size == 0 || !pe_data) {
                printf("  FAIL: pe_writer_emit failed\n");
                failed++;
            } else {
                FILE* f = fopen("test_encoded.exe", "wb");
                if (f) {
                    fwrite(pe_data, 1, pe_size, f);
                    fclose(f);
                    printf("  Generated: test_encoded.exe (%u bytes)\n", pe_size);
                    
                    printf("  Attempting to execute...\n");
                    STARTUPINFOA si = {sizeof(si)};
                    PROCESS_INFORMATION pi = {0};
                    
                    if (CreateProcessA("test_encoded.exe", NULL, NULL, NULL, FALSE,
                                      0, NULL, NULL, &si, &pi)) {
                        WaitForSingleObject(pi.hProcess, INFINITE);
                        
                        DWORD exit_code;
                        if (GetExitCodeProcess(pi.hProcess, &exit_code)) {
                            if (exit_code == 123) {
                                printf("  PASS: Exit code = %lu (expected 123)\n", exit_code);
                                passed++;
                            } else {
                                printf("  FAIL: Exit code = %lu (expected 123)\n", exit_code);
                                failed++;
                            }
                        } else {
                            printf("  FAIL: Could not get exit code\n");
                            failed++;
                        }
                        
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                    } else {
                        printf("  FAIL: Could not create process (error %lu)\n", GetLastError());
                        failed++;
                    }
                } else {
                    printf("  FAIL: Could not write file\n");
                    failed++;
                }
                
                free(pe_data);
            }
            
            pe_writer_destroy(pw);
        }
    }
    
    // Test 3: Generate PE with ALU program
    printf("\nTest 3: Generate PE with ALU program (10 + 32 = 42)\n");
    {
        uint8_t code[32];
        size_t offset = 0;
        
        // mov rax, 10
        x64_operand_t rax = {.type = OP_REG, .size = SZ_QWORD, .reg = REG_RAX};
        x64_operand_t imm = {.type = OP_IMM, .size = SZ_QWORD, .imm = 10};
        x64_encoded_t enc = x64_encode_safe(MNEM_MOV, &rax, &imm, NULL);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // add rax, 32
        imm.imm = 32;
        enc = x64_encode_safe(MNEM_ADD, &rax, &imm, NULL);
        memcpy(code + offset, enc.bytes, enc.len); offset += enc.len;
        
        // ret
        code[offset++] = 0xC3;
        
        printf("  Encoded %zu bytes: ", offset);
        for (size_t i = 0; i < offset; i++) {
            printf("%02X ", code[i]);
        }
        printf("\n");
        
        PeWriter* pw = pe_writer_create();
        if (!pw) {
            printf("  FAIL: pe_writer_create failed\n");
            failed++;
        } else {
            pe_writer_set_entry(pw, 0);
            pe_writer_add_text(pw, code, (uint32_t)offset);
            
            uint8_t* pe_data = NULL;
            uint32_t pe_size = pe_writer_emit(pw, &pe_data);
            
            if (pe_size == 0 || !pe_data) {
                printf("  FAIL: pe_writer_emit failed\n");
                failed++;
            } else {
                FILE* f = fopen("test_alu.exe", "wb");
                if (f) {
                    fwrite(pe_data, 1, pe_size, f);
                    fclose(f);
                    printf("  Generated: test_alu.exe (%u bytes)\n", pe_size);
                    
                    printf("  Attempting to execute...\n");
                    STARTUPINFOA si = {sizeof(si)};
                    PROCESS_INFORMATION pi = {0};
                    
                    if (CreateProcessA("test_alu.exe", NULL, NULL, NULL, FALSE,
                                      0, NULL, NULL, &si, &pi)) {
                        WaitForSingleObject(pi.hProcess, INFINITE);
                        
                        DWORD exit_code;
                        if (GetExitCodeProcess(pi.hProcess, &exit_code)) {
                            if (exit_code == 42) {
                                printf("  PASS: Exit code = %lu (expected 42)\n", exit_code);
                                passed++;
                            } else {
                                printf("  FAIL: Exit code = %lu (expected 42)\n", exit_code);
                                failed++;
                            }
                        } else {
                            printf("  FAIL: Could not get exit code\n");
                            failed++;
                        }
                        
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                    } else {
                        printf("  FAIL: Could not create process (error %lu)\n", GetLastError());
                        failed++;
                    }
                } else {
                    printf("  FAIL: Could not write file\n");
                    failed++;
                }
                
                free(pe_data);
            }
            
            pe_writer_destroy(pw);
        }
    }
    
    // Cleanup
    remove("test_hardcoded.exe");
    remove("test_encoded.exe");
    remove("test_alu.exe");
    
    printf("\n==========================================================================\n");
    printf("PE INTEGRATION SUMMARY\n");
    printf("==========================================================================\n");
    printf("Total Tests: %d\n", passed + failed);
    printf("  PASSED: %d\n", passed);
    printf("  FAILED: %d\n", failed);
    printf("\nStatus: %s\n", (failed == 0) ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    printf("==========================================================================\n");
    
    return (failed == 0) ? 0 : 1;
}
