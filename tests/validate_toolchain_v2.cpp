/*==========================================================================
 * From-Scratch Toolchain Validation Harness - SIMPLIFIED
 * Tests: x64_encoder
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

// From-scratch toolchain (C linkage)
extern "C" {
#include "x64_encoder.h"
}

// ============================================================================
// Test Result Tracking
// ============================================================================
static int g_passed = 0;
static int g_failed = 0;
static std::vector<std::string> g_failures;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            g_failed++; \
            std::stringstream ss; \
            ss << "FAIL: " << __FILE__ << ":" << __LINE__ << " - " << msg; \
            g_failures.push_back(ss.str()); \
            std::cerr << ss.str() << std::endl; \
        } else { \
            g_passed++; \
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
    {
        x64_operand_t dst;
        memset(&dst, 0, sizeof(dst));
        dst.type = OP_REG;
        dst.size = SZ_QWORD;
        dst.u.reg = REG_RAX;
        
        x64_operand_t src;
        memset(&src, 0, sizeof(src));
        src.type = OP_REG;
        src.size = SZ_QWORD;
        src.u.reg = REG_RBX;
        
        x64_encoded_t enc = x64_encode(MNEM_MOV, &dst, &src);
        
        TEST_ASSERT(enc.len == 3, "mov rax, rbx should be 3 bytes");
        TEST_ASSERT(enc.bytes[0] == 0x48, "REX.W prefix should be 0x48");
        TEST_ASSERT(enc.bytes[1] == 0x89, "MOV opcode should be 0x89");
        TEST_ASSERT(enc.bytes[2] == 0xD8, "ModRM should be 0xD8");
        
        std::cout << "  mov rax, rbx: " << bytesToHex(enc.bytes, enc.len) << std::endl;
    }
    
    // Test: add rax, rcx
    {
        x64_operand_t dst;
        memset(&dst, 0, sizeof(dst));
        dst.type = OP_REG;
        dst.size = SZ_QWORD;
        dst.u.reg = REG_RAX;
        
        x64_operand_t src;
        memset(&src, 0, sizeof(src));
        src.type = OP_REG;
        src.size = SZ_QWORD;
        src.u.reg = REG_RCX;
        
        x64_encoded_t enc = x64_encode(MNEM_ADD, &dst, &src);
        
        TEST_ASSERT(enc.len == 3, "add rax, rcx should be 3 bytes");
        
        std::cout << "  add rax, rcx: " << bytesToHex(enc.bytes, enc.len) << std::endl;
    }
    
    // Test: xor r8, r9
    {
        x64_operand_t dst;
        memset(&dst, 0, sizeof(dst));
        dst.type = OP_REG;
        dst.size = SZ_QWORD;
        dst.u.reg = REG_R8;
        
        x64_operand_t src;
        memset(&src, 0, sizeof(src));
        src.type = OP_REG;
        src.size = SZ_QWORD;
        src.u.reg = REG_R9;
        
        x64_encoded_t enc = x64_encode(MNEM_XOR, &dst, &src);
        
        TEST_ASSERT(enc.len == 3, "xor r8, r9 should be 3 bytes");
        TEST_ASSERT(enc.bytes[0] == 0x4D, "REX.WB prefix should be 0x4D");
        
        std::cout << "  xor r8, r9: " << bytesToHex(enc.bytes, enc.len) << std::endl;
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
        memset(&dst, 0, sizeof(dst));
        dst.type = OP_REG;
        dst.size = SZ_QWORD;
        dst.u.reg = REG_RAX;
        
        x64_operand_t src;
        memset(&src, 0, sizeof(src));
        src.type = OP_MEM;
        src.size = SZ_QWORD;
        src.u.mem.base = REG_RBX;
        src.u.mem.index = REG_NONE;
        src.u.mem.scale = 0;
        src.u.mem.disp = 0;
        src.u.mem.has_disp = 0;
        
        x64_encoded_t enc = x64_encode(MNEM_MOV, &dst, &src);
        
        TEST_ASSERT(enc.len > 0, "mov rax, [rbx] encoding failed");
        
        std::cout << "  mov rax, [rbx]: " << bytesToHex(enc.bytes, enc.len) << std::endl;
    }
    
    std::cout << "  Memory operand tests complete" << std::endl;
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
    
    std::cout << "\n==========================================================================" << std::endl;
    std::cout << "Test Summary:" << std::endl;
    std::cout << "  Passed: " << g_passed << std::endl;
    std::cout << "  Failed: " << g_failed << std::endl;
    std::cout << "==========================================================================" << std::endl;
    
    if (g_failed > 0) {
        std::cout << "\nFailures:" << std::endl;
        for (const auto& f : g_failures) {
            std::cout << "  " << f << std::endl;
        }
        return 1;
    }
    
    std::cout << "\nAll tests PASSED!" << std::endl;
    return 0;
}
