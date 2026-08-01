/*==========================================================================
 * From-Scratch Toolchain Validation Harness
 * Tests: x64_encoder, coff_writer
 *=========================================================================*/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <windows.h>
#include <shlwapi.h>

// From-scratch toolchain (C linkage)
extern "C" {
#include "x64_encoder.h"
#include "coff_writer.h"
}

// ============================================================================
// Test Result Tracking
// ============================================================================
struct TestStats {
    int passed = 0;
    int failed = 0;
    std::vector<std::string> failures;
};

static TestStats g_stats;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            g_stats.failed++; \
            std::stringstream ss; \
            ss << "FAIL: " << __FILE__ << ":" << __LINE__ << " - " << msg; \
            g_stats.failures.push_back(ss.str()); \
            std::cerr << ss.str() << std::endl; \
        } else { \
            g_stats.passed++; \
        } \
    } while(0)

// ============================================================================
// Helper: Dump bytes as hex
// ============================================================================
static std::string bytesToHex(const uint8_t* bytes, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
        if (i < len - 1) ss << " ";
    }
    return ss.str();
}

// ============================================================================
// Test 1: x64 Encoder - Basic Instruction Encoding
// ============================================================================
void test_x64_encoder_basic() {
    std::cout << "\n=== Test: x64 Encoder - Basic Instructions ===" << std::endl;
    
    // Test: mov rax, rbx
    // Expected: 48 89 D8 (REX.W + opcode 89 + ModRM)
    {
        x64_operand_t dst;
        dst.type = OP_REG;
        dst.size = SZ_QWORD;
        dst.reg = REG_RAX;
        
        x64_operand_t src;
        src.type = OP_REG;
        src.size = SZ_QWORD;
        src.reg = REG_RBX;
        
        x64_encoded_t enc = x64_encode(MNEM_MOV, &dst, &src);
        
        TEST_ASSERT(enc.len == 3, "mov rax, rbx should be 3 bytes");
        TEST_ASSERT(enc.bytes[0] == 0x48, "REX.W prefix should be 0x48");
        TEST_ASSERT(enc.bytes[1] == 0x89, "MOV opcode should be 0x89");
        TEST_ASSERT(enc.bytes[2] == 0xD8, "ModRM should be 0xD8 (11 011 000)");
        
        std::cout << "  mov rax, rbx: " << bytesToHex(enc.bytes, enc.len) << std::endl;
    }
    
    // Test: add rax, rcx
    // Expected: 48 01 C8
    {
        x64_operand_t dst;
        dst.type = OP_REG;
        dst.size = SZ_QWORD;
        dst.reg = REG_RAX;
        
        x64_operand_t src;
        src.type = OP_REG;
        src.size = SZ_QWORD;
        src.reg = REG_RCX;
        
        x64_encoded_t enc = x64_encode(MNEM_ADD, &dst, &src);
        
        TEST_ASSERT(enc.len == 3, "add rax, rcx should be 3 bytes");
        
        std::cout << "  add rax, rcx: " << bytesToHex(enc.bytes, enc.len) << std::endl;
    }
    
    // Test: xor r8, r9 (extended registers)
    // Expected: 4D 31 C8 (REX.WB + opcode 31 + ModRM)
    {
        x64_operand_t dst;
        dst.type = OP_REG;
        dst.size = SZ_QWORD;
        dst.reg = REG_R8;
        
        x64_operand_t src;
        src.type = OP_REG;
        src.size = SZ_QWORD;
        src.reg = REG_R9;
        
        x64_encoded_t enc = x64_encode(MNEM_XOR, &dst, &src);
        
        TEST_ASSERT(enc.len == 3, "xor r8, r9 should be 3 bytes");
        TEST_ASSERT(enc.bytes[0] == 0x4D, "REX.WB prefix should be 0x4D");
        
        std::cout << "  xor r8, r9: " << bytesToHex(enc.bytes, enc.len) << std::endl;
    }
    
    // Test: mov rax, imm64
    // Expected: 48 B8 + 8 bytes immediate
    {
        x64_operand_t dst;
        dst.type = OP_REG;
        dst.size = SZ_QWORD;
        dst.reg = REG_RAX;
        
        x64_operand_t src;
        src.type = OP_IMM;
        src.size = SZ_QWORD;
        src.imm = 0x123456789ABCDEF0LL;
        
        x64_encoded_t enc = x64_encode(MNEM_MOV, &dst, &src);
        
        TEST_ASSERT(enc.len == 10, "mov rax, imm64 should be 10 bytes");
        TEST_ASSERT(enc.bytes[0] == 0x48, "REX.W prefix should be 0x48");
        TEST_ASSERT(enc.bytes[1] == 0xB8, "MOV r64, imm64 opcode should be 0xB8");
        
        std::cout << "  mov rax, 0x123456789ABCDEF0: " << bytesToHex(enc.bytes, enc.len) << std::endl;
    }
    
    std::cout << "  Basic encoding tests complete" << std::endl;
}

// ============================================================================
// Test 2: x64 Encoder - Memory Operands
// ============================================================================
void test_x64_encoder_memory() {
    std::cout << "\n=== Test: x64 Encoder - Memory Operands ===" << std::endl;
    
    // Test: mov rax, [rbx]
    {
        x64_operand_t dst;
        dst.type = OP_REG;
        dst.size = SZ_QWORD;
        dst.reg = REG_RAX;
        
        x64_operand_t src;
        src.type = OP_MEM;
        src.size = SZ_QWORD;
        src.mem.base = REG_RBX;
        src.mem.index = REG_NONE;
        src.mem.scale = 0;
        src.mem.disp = 0;
        src.mem.has_disp = 0;
        
        x64_encoded_t enc = x64_encode(MNEM_MOV, &dst, &src);
        
        TEST_ASSERT(enc.len > 0, "mov rax, [rbx] encoding failed");
        
        std::cout << "  mov rax, [rbx]: " << bytesToHex(enc.bytes, enc.len) << std::endl;
    }
    
    // Test: mov rax, [rsp+8]
    {
        x64_operand_t dst;
        dst.type = OP_REG;
        dst.size = SZ_QWORD;
        dst.reg = REG_RAX;
        
        x64_operand_t src;
        src.type = OP_MEM;
        src.size = SZ_QWORD;
        src.mem.base = REG_RSP;
        src.mem.index = REG_NONE;
        src.mem.scale = 0;
        src.mem.disp = 8;
        src.mem.has_disp = 1;
        
        x64_encoded_t enc = x64_encode(MNEM_MOV, &dst, &src);
        
        TEST_ASSERT(enc.len > 0, "mov rax, [rsp+8] encoding failed");
        
        std::cout << "  mov rax, [rsp+8]: " << bytesToHex(enc.bytes, enc.len) << std::endl;
    }
    
    std::cout << "  Memory operand tests complete" << std::endl;
}

// ============================================================================
// Test 3: COFF Writer - Object File Generation
// ============================================================================
void test_coff_writer() {
    std::cout << "\n=== Test: COFF Writer - Object File Generation ===" << std::endl;
    
    const char* test_obj = "test_output.obj";
    
    // Create a minimal COFF file
    coff_file_t* coff = coff_file_create();
    TEST_ASSERT(coff != nullptr, "Failed to create COFF file");
    
    // Add .text section with some code
    const uint8_t code[] = {
        0x48, 0x89, 0xD8,  // mov rax, rbx
        0x48, 0x01, 0xC8,  // add rax, rcx
        0xC3               // ret
    };
    
    int section_idx = coff_add_section(coff, ".text", 
                                       SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ,
                                       code, sizeof(code));
    TEST_ASSERT(section_idx >= 0, "Failed to add .text section");
    
    // Add a symbol
    int sym_idx = coff_add_symbol(coff, "_start", section_idx, 0, 
                                  SYM_CLASS_EXTERNAL);
    TEST_ASSERT(sym_idx >= 0, "Failed to add symbol");
    
    // Write to file
    int result = coff_file_write(coff, test_obj);
    TEST_ASSERT(result == 0, "Failed to write COFF file");
    
    coff_file_free(coff);
    
    // Verify file exists and has reasonable size
    std::ifstream file(test_obj, std::ios::binary | std::ios::ate);
    TEST_ASSERT(file.is_open(), "COFF file was not created");
    
    auto size = file.tellg();
    TEST_ASSERT(size > 0, "COFF file is empty");
    TEST_ASSERT(size >= 64, "COFF file too small (header alone is ~64 bytes)");
    
    file.seekg(0, std::ios::beg);
    
    // Verify COFF magic number
    uint16_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    TEST_ASSERT(magic == 0x8664 || magic == 0x014C, "Invalid COFF magic number");
    
    file.close();
    
    // Cleanup
    DeleteFileA(test_obj);
    
    std::cout << "  COFF object file generation: PASSED (" << size << " bytes)" << std::endl;
}

// ============================================================================
// Main Entry Point
// ============================================================================
int main() {
    std::cout << "==========================================================================" << std::endl;
    std::cout << "RawrXD From-Scratch Toolchain Validation" << std::endl;
    std::cout << "==========================================================================" << std::endl;
    
    test_x64_encoder_basic();
    test_x64_encoder_memory();
    test_coff_writer();
    
    std::cout << "\n==========================================================================" << std::endl;
    std::cout << "Test Summary:" << std::endl;
    std::cout << "  Passed: " << g_stats.passed << std::endl;
    std::cout << "  Failed: " << g_stats.failed << std::endl;
    std::cout << "==========================================================================" << std::endl;
    
    if (g_stats.failed > 0) {
        std::cout << "\nFailures:" << std::endl;
        for (const auto& f : g_stats.failures) {
            std::cout << "  " << f << std::endl;
        }
        return 1;
    }
    
    std::cout << "\nAll tests PASSED!" << std::endl;
    return 0;
}
