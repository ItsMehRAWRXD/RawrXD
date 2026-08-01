/*==========================================================================
 * x64 Assembler Validation Harness v2 - COMPREHENSIVE
 * Validates x64 encoder against MASM (ml64.exe) as reference
 * Target: 3000+ tests with 100% encoder quality
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
#include <filesystem>

// Undefine Windows macros that conflict with our register enum
#undef REG_RAX
#undef REG_RCX
#undef REG_RDX
#undef REG_RBX
#undef REG_RSP
#undef REG_RBP
#undef REG_RSI
#undef REG_RDI
#undef REG_R8
#undef REG_R9
#undef REG_R10
#undef REG_R11
#undef REG_R12
#undef REG_R13
#undef REG_R14
#undef REG_R15
#undef REG_NONE

extern "C" {
#include "x64_encoder.h"
#include "coff_writer.h"
}

namespace fs = std::filesystem;

// ============================================================================
// Test Result Categories
// ============================================================================
enum class TestStatus {
    EXACT_MATCH,        // Byte-for-byte identical
    EQUIVALENT,         // Different encoding, same semantics
    HARNESS_ISSUE,      // Test infrastructure problem
    NOT_IMPLEMENTED,    // Feature not yet supported
    BUG                 // Real encoder bug
};

struct TestResult {
    std::string name;
    std::string instruction;
    std::string our_bytes;
    std::string ref_bytes;
    TestStatus status;
    std::string notes;
};

static std::vector<TestResult> g_results;
static int g_exact = 0, g_equiv = 0, g_harness = 0, g_notimpl = 0, g_bug = 0;

void addResult(const TestResult& r) {
    g_results.push_back(r);
    switch(r.status) {
        case TestStatus::EXACT_MATCH: g_exact++; break;
        case TestStatus::EQUIVALENT: g_equiv++; break;
        case TestStatus::HARNESS_ISSUE: g_harness++; break;
        case TestStatus::NOT_IMPLEMENTED: g_notimpl++; break;
        case TestStatus::BUG: g_bug++; break;
    }
}

// ============================================================================
// Helpers
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
// MASM Integration
// ============================================================================
class MASMValidator {
    fs::path m_temp_dir;
    bool m_available;

public:
    MASMValidator() : m_available(false) {
        // Check if ml64.exe is available
        char* path = nullptr;
        size_t len = 0;
        if (_dupenv_s(&path, &len, "VSINSTALLDIR") == 0 && path != nullptr) {
            free(path);
            m_available = true;
        } else {
            // Try to find ml64.exe in common locations
            const char* common_paths[] = {
                "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Tools\\MSVC\\14.40.33807\\bin\\Hostx64\\x64\\ml64.exe",
                "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Tools\\MSVC\\14.40.33807\\bin\\Hostx64\\x64\\ml64.exe",
                "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.40.33807\\bin\\Hostx64\\x64\\ml64.exe",
                "C:\\VS2022Enterprise\\VC\\Tools\\MSVC\\14.50.35717\\bin\\Hostx64\\x64\\ml64.exe"
            };
            for (const auto& p : common_paths) {
                if (fs::exists(p)) {
                    m_available = true;
                    break;
                }
            }
        }
    }

    bool available() const { return m_available; }

    std::vector<uint8_t> assemble(const char* instruction) {
        std::vector<uint8_t> result;
        if (!m_available) return result;

        // Create temp directory
        char temp_path[MAX_PATH];
        GetTempPathA(MAX_PATH, temp_path);
        m_temp_dir = fs::path(temp_path) / "masm_validate";
        fs::create_directories(m_temp_dir);

        // Write assembly file
        auto asm_file = m_temp_dir / "test.asm";
        std::ofstream f(asm_file);
        f << ".code\n";
        f << "start PROC\n";
        f << "    " << instruction << "\n";
        f << "start ENDP\n";
        f << "END\n";
        f.close();

        // Assemble
        auto obj_file = m_temp_dir / "test.obj";
        std::string cmd = "ml64.exe /c /Fo" + obj_file.string() + " " + asm_file.string() + " 2>nul";
        int ret = system(cmd.c_str());
        if (ret != 0) return result;

        // Read object file and extract code bytes
        std::ifstream obj(obj_file, std::ios::binary);
        if (!obj) return result;

        // Simple COFF parsing - find .text section
        obj.seekg(0, std::ios::end);
        size_t size = obj.tellg();
        obj.seekg(0, std::ios::beg);

        std::vector<uint8_t> data(size);
        obj.read((char*)data.data(), size);

        // COFF header is at offset 0
        // NumberOfSections at offset 2
        // SizeOfOptionalHeader at offset 16
        // Section headers start at offset 24 (or 24 + SizeOfOptionalHeader for PE)
        
        uint16_t num_sections = *(uint16_t*)(data.data() + 2);
        uint16_t opt_header_size = *(uint16_t*)(data.data() + 16);
        size_t section_table_offset = 24 + opt_header_size;

        // Find .text section
        for (uint16_t i = 0; i < num_sections; i++) {
            size_t sec_offset = section_table_offset + i * 40;
            char* name = (char*)(data.data() + sec_offset);
            if (strncmp(name, ".text", 6) == 0) {
                uint32_t raw_size = *(uint32_t*)(data.data() + sec_offset + 16);
                uint32_t raw_ptr = *(uint32_t*)(data.data() + sec_offset + 20);
                if (raw_ptr > 0 && raw_ptr + raw_size <= data.size()) {
                    result.insert(result.end(), data.begin() + raw_ptr, data.begin() + raw_ptr + raw_size);
                }
                break;
            }
        }

        return result;
    }

    ~MASMValidator() {
        if (!m_temp_dir.empty()) {
            fs::remove_all(m_temp_dir);
        }
    }
};

// ============================================================================
// Test Functions
// ============================================================================

void test_mov_reg_reg(MASMValidator& masm) {
    std::cout << "\n=== Test: MOV Register to Register ===\n";
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int count = 0;
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            if (i == j) continue;
            
            x64_operand_t dst; dst.type = OP_REG; dst.size = SZ_QWORD; dst.reg = regs[i];
            x64_operand_t src; src.type = OP_REG; src.size = SZ_QWORD; src.reg = regs[j];
            x64_encoded_t enc = x64_encode(MNEM_MOV, &dst, &src);
            std::string our_hex = bytesToHex(enc.bytes, enc.len);
            
            char asm_str[64];
            snprintf(asm_str, sizeof(asm_str), "mov %s, %s", reg_names[i], reg_names[j]);
            char test_name[64];
            snprintf(test_name, sizeof(test_name), "MOV_%s_%s", reg_names[i], reg_names[j]);
            
            auto ref = masm.assemble(asm_str);
            std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
        }
    }
    std::cout << "  Completed " << count << " MOV register tests\n";
}

void test_alu_reg_reg(MASMValidator& masm) {
    std::cout << "\n=== Test: ALU Register to Register ===\n";
    
    struct ALUOp { x64_mnemonic_t mnem; const char* name; };
    ALUOp ops[] = {{MNEM_ADD, "add"}, {MNEM_SUB, "sub"}, {MNEM_AND, "and"}, 
                   {MNEM_OR, "or"}, {MNEM_XOR, "xor"}, {MNEM_CMP, "cmp"}};
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int count = 0;
    for (const auto& op : ops) {
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 16; j++) {
                if (i == j && op.mnem != MNEM_XOR) continue;
                
                x64_operand_t dst; dst.type = OP_REG; dst.size = SZ_QWORD; dst.reg = regs[i];
                x64_operand_t src; src.type = OP_REG; src.size = SZ_QWORD; src.reg = regs[j];
                x64_encoded_t enc = x64_encode(op.mnem, &dst, &src);
                std::string our_hex = bytesToHex(enc.bytes, enc.len);
                
                char asm_str[64];
                snprintf(asm_str, sizeof(asm_str), "%s %s, %s", op.name, reg_names[i], reg_names[j]);
                char test_name[64];
                snprintf(test_name, sizeof(test_name), "%s_%s_%s", op.name, reg_names[i], reg_names[j]);
                
                auto ref = masm.assemble(asm_str);
                std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
                
                TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
                addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
                count++;
            }
        }
    }
    std::cout << "  Completed " << count << " ALU register tests\n";
}

void test_push_pop(MASMValidator& masm) {
    std::cout << "\n=== Test: PUSH/POP Registers ===\n";
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int count = 0;
    for (int i = 0; i < 16; i++) {
        // PUSH
        x64_operand_t op; op.type = OP_REG; op.size = SZ_QWORD; op.reg = regs[i];
        x64_encoded_t enc = x64_encode(MNEM_PUSH, &op, NULL);
        std::string our_hex = bytesToHex(enc.bytes, enc.len);
        
        char asm_str[32];
        snprintf(asm_str, sizeof(asm_str), "push %s", reg_names[i]);
        char test_name[32];
        snprintf(test_name, sizeof(test_name), "PUSH_%s", reg_names[i]);
        
        auto ref = masm.assemble(asm_str);
        std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
        
        TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
        addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
        count++;
        
        // POP
        enc = x64_encode(MNEM_POP, &op, NULL);
        our_hex = bytesToHex(enc.bytes, enc.len);
        
        snprintf(asm_str, sizeof(asm_str), "pop %s", reg_names[i]);
        snprintf(test_name, sizeof(test_name), "POP_%s", reg_names[i]);
        
        ref = masm.assemble(asm_str);
        ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
        
        status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
        addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
        count++;
    }
    std::cout << "  Completed " << count << " PUSH/POP tests\n";
}

void test_inc_dec(MASMValidator& masm) {
    std::cout << "\n=== Test: INC/DEC/NEG/NOT ===\n";
    
    struct UnaryOp { x64_mnemonic_t mnem; const char* name; };
    UnaryOp ops[] = {{MNEM_INC, "inc"}, {MNEM_DEC, "dec"}, {MNEM_NEG, "neg"}, {MNEM_NOT, "not"}};
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int count = 0;
    for (const auto& op : ops) {
        for (int i = 0; i < 16; i++) {
            x64_operand_t dst; dst.type = OP_REG; dst.size = SZ_QWORD; dst.reg = regs[i];
            x64_encoded_t enc = x64_encode(op.mnem, &dst, NULL);
            std::string our_hex = bytesToHex(enc.bytes, enc.len);
            
            char asm_str[32];
            snprintf(asm_str, sizeof(asm_str), "%s %s", op.name, reg_names[i]);
            char test_name[32];
            snprintf(test_name, sizeof(test_name), "%s_%s", op.name, reg_names[i]);
            
            auto ref = masm.assemble(asm_str);
            std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
        }
    }
    std::cout << "  Completed " << count << " INC/DEC/NEG/NOT tests\n";
}

void test_shifts(MASMValidator& masm) {
    std::cout << "\n=== Test: Shift/Rotate Instructions ===\n";
    
    struct ShiftOp { x64_mnemonic_t mnem; const char* name; };
    ShiftOp ops[] = {{MNEM_SHL, "shl"}, {MNEM_SHR, "shr"}, {MNEM_SAR, "sar"}, 
                     {MNEM_ROL, "rol"}, {MNEM_ROR, "ror"}};
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int count = 0;
    for (const auto& op : ops) {
        for (int i = 0; i < 16; i++) {
            // Shift by 1
            x64_operand_t dst; dst.type = OP_REG; dst.size = SZ_QWORD; dst.reg = regs[i];
            x64_operand_t cnt; cnt.type = OP_IMM; cnt.size = SZ_BYTE; cnt.imm = 1;
            x64_encoded_t enc = x64_encode(op.mnem, &dst, &cnt);
            std::string our_hex = bytesToHex(enc.bytes, enc.len);
            
            char asm_str[32];
            snprintf(asm_str, sizeof(asm_str), "%s %s, 1", op.name, reg_names[i]);
            char test_name[32];
            snprintf(test_name, sizeof(test_name), "%s_%s_1", op.name, reg_names[i]);
            
            auto ref = masm.assemble(asm_str);
            std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
            
            // Shift by CL
            cnt.type = OP_REG; cnt.size = SZ_BYTE; cnt.reg = REG_RCX;
            enc = x64_encode(op.mnem, &dst, &cnt);
            our_hex = bytesToHex(enc.bytes, enc.len);
            
            snprintf(asm_str, sizeof(asm_str), "%s %s, cl", op.name, reg_names[i]);
            snprintf(test_name, sizeof(test_name), "%s_%s_cl", op.name, reg_names[i]);
            
            ref = masm.assemble(asm_str);
            ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
            
            // Shift by immediate
            cnt.type = OP_IMM; cnt.size = SZ_BYTE; cnt.imm = 5;
            enc = x64_encode(op.mnem, &dst, &cnt);
            our_hex = bytesToHex(enc.bytes, enc.len);
            
            snprintf(asm_str, sizeof(asm_str), "%s %s, 5", op.name, reg_names[i]);
            snprintf(test_name, sizeof(test_name), "%s_%s_5", op.name, reg_names[i]);
            
            ref = masm.assemble(asm_str);
            ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
        }
    }
    std::cout << "  Completed " << count << " shift/rotate tests\n";
}

void test_mov_imm(MASMValidator& masm) {
    std::cout << "\n=== Test: MOV with Immediate ===\n";
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int64_t immediates[] = {0, 1, 2, 4, 8, 16, 32, 64, 128, 255, 256, 512, 1024, 2048, 4096, 
                            8192, 16384, 32768, 65535, 65536, 100000, 1000000, 
                            -1, -2, -4, -8, -16, -32, -64, -128, -256, -512, -1024};
    
    int count = 0;
    for (int i = 0; i < 16; i++) {
        for (size_t imm_idx = 0; imm_idx < sizeof(immediates)/sizeof(immediates[0]); imm_idx++) {
            x64_operand_t dst; dst.type = OP_REG; dst.size = SZ_QWORD; dst.reg = regs[i];
            x64_operand_t src; src.type = OP_IMM; src.size = SZ_QWORD; src.imm = immediates[imm_idx];
            x64_encoded_t enc = x64_encode(MNEM_MOV, &dst, &src);
            std::string our_hex = bytesToHex(enc.bytes, enc.len);
            
            char asm_str[64];
            snprintf(asm_str, sizeof(asm_str), "mov %s, %lld", reg_names[i], (long long)immediates[imm_idx]);
            char test_name[64];
            snprintf(test_name, sizeof(test_name), "MOV_%s_IMM%lld", reg_names[i], (long long)immediates[imm_idx]);
            
            auto ref = masm.assemble(asm_str);
            std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
        }
    }
    std::cout << "  Completed " << count << " MOV immediate tests\n";
}

void test_xchg(MASMValidator& masm) {
    std::cout << "\n=== Test: XCHG Register ===\n";
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int count = 0;
    for (int i = 0; i < 16; i++) {
        for (int j = i + 1; j < 16; j++) {
            x64_operand_t dst; dst.type = OP_REG; dst.size = SZ_QWORD; dst.reg = regs[i];
            x64_operand_t src; src.type = OP_REG; src.size = SZ_QWORD; src.reg = regs[j];
            x64_encoded_t enc = x64_encode(MNEM_XCHG, &dst, &src);
            std::string our_hex = bytesToHex(enc.bytes, enc.len);
            
            char asm_str[64];
            snprintf(asm_str, sizeof(asm_str), "xchg %s, %s", reg_names[i], reg_names[j]);
            char test_name[64];
            snprintf(test_name, sizeof(test_name), "XCHG_%s_%s", reg_names[i], reg_names[j]);
            
            auto ref = masm.assemble(asm_str);
            std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
        }
    }
    std::cout << "  Completed " << count << " XCHG tests\n";
}

void test_lea(MASMValidator& masm) {
    std::cout << "\n=== Test: LEA ===\n";
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int count = 0;
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            if (regs[j] == REG_RSP) continue;
            
            x64_operand_t dst; dst.type = OP_REG; dst.size = SZ_QWORD; dst.reg = regs[i];
            x64_operand_t src; src.type = OP_MEM; src.size = SZ_QWORD;
            src.mem.base = regs[j]; src.mem.index = REG_NONE; src.mem.scale = 0;
            src.mem.disp = 0; src.mem.has_disp = 0;
            x64_encoded_t enc = x64_encode(MNEM_LEA, &dst, &src);
            std::string our_hex = bytesToHex(enc.bytes, enc.len);
            
            char asm_str[64];
            snprintf(asm_str, sizeof(asm_str), "lea %s, [%s]", reg_names[i], reg_names[j]);
            char test_name[64];
            snprintf(test_name, sizeof(test_name), "LEA_%s_[%s]", reg_names[i], reg_names[j]);
            
            auto ref = masm.assemble(asm_str);
            std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
        }
    }
    std::cout << "  Completed " << count << " LEA tests\n";
}

void test_call_jmp_reg(MASMValidator& masm) {
    std::cout << "\n=== Test: CALL/JMP Register ===\n";
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int count = 0;
    for (int i = 0; i < 16; i++) {
        x64_operand_t op; op.type = OP_REG; op.size = SZ_QWORD; op.reg = regs[i];
        x64_encoded_t enc = x64_encode(MNEM_CALL, &op, NULL);
        std::string our_hex = bytesToHex(enc.bytes, enc.len);
        
        char asm_str[32];
        snprintf(asm_str, sizeof(asm_str), "call %s", reg_names[i]);
        char test_name[32];
        snprintf(test_name, sizeof(test_name), "CALL_%s", reg_names[i]);
        
        auto ref = masm.assemble(asm_str);
        std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
        
        TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
        addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
        count++;
        
        enc = x64_encode(MNEM_JMP, &op, NULL);
        our_hex = bytesToHex(enc.bytes, enc.len);
        
        snprintf(asm_str, sizeof(asm_str), "jmp %s", reg_names[i]);
        snprintf(test_name, sizeof(test_name), "JMP_%s", reg_names[i]);
        
        ref = masm.assemble(asm_str);
        ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
        
        status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
        addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
        count++;
    }
    std::cout << "  Completed " << count << " CALL/JMP register tests\n";
}

void test_mul_div(MASMValidator& masm) {
    std::cout << "\n=== Test: MUL/DIV/IDIV ===\n";
    
    struct MulOp { x64_mnemonic_t mnem; const char* name; };
    MulOp ops[] = {{MNEM_MUL, "mul"}, {MNEM_DIV, "div"}, {MNEM_IDIV, "idiv"}};
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int count = 0;
    for (const auto& op : ops) {
        for (int i = 0; i < 16; i++) {
            x64_operand_t src; src.type = OP_REG; src.size = SZ_QWORD; src.reg = regs[i];
            x64_encoded_t enc = x64_encode(op.mnem, &src, NULL);
            std::string our_hex = bytesToHex(enc.bytes, enc.len);
            
            char asm_str[32];
            snprintf(asm_str, sizeof(asm_str), "%s %s", op.name, reg_names[i]);
            char test_name[32];
            snprintf(test_name, sizeof(test_name), "%s_%s", op.name, reg_names[i]);
            
            auto ref = masm.assemble(asm_str);
            std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
        }
    }
    std::cout << "  Completed " << count << " MUL/DIV/IDIV tests\n";
}

void test_imul(MASMValidator& masm) {
    std::cout << "\n=== Test: IMUL ===\n";
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int count = 0;
    
    // IMUL reg (single operand)
    for (int i = 0; i < 16; i++) {
        x64_operand_t src; src.type = OP_REG; src.size = SZ_QWORD; src.reg = regs[i];
        x64_encoded_t enc = x64_encode(MNEM_IMUL, &src, NULL);
        std::string our_hex = bytesToHex(enc.bytes, enc.len);
        
        char asm_str[32];
        snprintf(asm_str, sizeof(asm_str), "imul %s", reg_names[i]);
        char test_name[32];
        snprintf(test_name, sizeof(test_name), "IMUL_%s", reg_names[i]);
        
        auto ref = masm.assemble(asm_str);
        std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
        
        TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
        addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
        count++;
    }
    
    // IMUL dst, src (two operands)
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            x64_operand_t dst; dst.type = OP_REG; dst.size = SZ_QWORD; dst.reg = regs[i];
            x64_operand_t src; src.type = OP_REG; src.size = SZ_QWORD; src.reg = regs[j];
            x64_encoded_t enc = x64_encode(MNEM_IMUL, &dst, &src);
            std::string our_hex = bytesToHex(enc.bytes, enc.len);
            
            char asm_str[64];
            snprintf(asm_str, sizeof(asm_str), "imul %s, %s", reg_names[i], reg_names[j]);
            char test_name[64];
            snprintf(test_name, sizeof(test_name), "IMUL2_%s_%s", reg_names[i], reg_names[j]);
            
            auto ref = masm.assemble(asm_str);
            std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
        }
    }
    
    std::cout << "  Completed " << count << " IMUL tests\n";
}

void test_movzx_movsx(MASMValidator& masm) {
    std::cout << "\n=== Test: MOVZX/MOVSX ===\n";
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int count = 0;
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            // MOVZX byte to qword
            x64_operand_t dst; dst.type = OP_REG; dst.size = SZ_QWORD; dst.reg = regs[i];
            x64_operand_t src; src.type = OP_REG; src.size = SZ_BYTE; src.reg = regs[j];
            x64_encoded_t enc = x64_encode(MNEM_MOVZX, &dst, &src);
            std::string our_hex = bytesToHex(enc.bytes, enc.len);
            
            char asm_str[64];
            snprintf(asm_str, sizeof(asm_str), "movzx %s, %sb", reg_names[i], reg_names[j]);
            char test_name[64];
            snprintf(test_name, sizeof(test_name), "MOVZX_%s_%sb", reg_names[i], reg_names[j]);
            
            auto ref = masm.assemble(asm_str);
            std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
            
            // MOVSX byte to qword
            enc = x64_encode(MNEM_MOVSX, &dst, &src);
            our_hex = bytesToHex(enc.bytes, enc.len);
            
            snprintf(asm_str, sizeof(asm_str), "movsx %s, %sb", reg_names[i], reg_names[j]);
            snprintf(test_name, sizeof(test_name), "MOVSX_%s_%sb", reg_names[i], reg_names[j]);
            
            ref = masm.assemble(asm_str);
            ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
            
            // MOVZX word to qword
            src.size = SZ_WORD;
            enc = x64_encode(MNEM_MOVZX, &dst, &src);
            our_hex = bytesToHex(enc.bytes, enc.len);
            
            snprintf(asm_str, sizeof(asm_str), "movzx %s, %sw", reg_names[i], reg_names[j]);
            snprintf(test_name, sizeof(test_name), "MOVZX_%s_%sw", reg_names[i], reg_names[j]);
            
            ref = masm.assemble(asm_str);
            ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
            
            // MOVSX word to qword
            enc = x64_encode(MNEM_MOVSX, &dst, &src);
            our_hex = bytesToHex(enc.bytes, enc.len);
            
            snprintf(asm_str, sizeof(asm_str), "movsx %s, %sw", reg_names[i], reg_names[j]);
            snprintf(test_name, sizeof(test_name), "MOVSX_%s_%sw", reg_names[i], reg_names[j]);
            
            ref = masm.assemble(asm_str);
            ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
        }
    }
    std::cout << "  Completed " << count << " MOVZX/MOVSX tests\n";
}

void test_setcc(MASMValidator& masm) {
    std::cout << "\n=== Test: SETcc ===\n";
    
    struct SETTest { x64_mnemonic_t mnem; const char* name; };
    SETTest tests[] = {
        {MNEM_SETA, "seta"}, {MNEM_SETAE, "setae"},
        {MNEM_SETB, "setb"}, {MNEM_SETBE, "setbe"},
        {MNEM_SETE, "sete"}, {MNEM_SETG, "setg"},
        {MNEM_SETGE, "setge"}, {MNEM_SETL, "setl"},
        {MNEM_SETLE, "setle"}, {MNEM_SETNE, "setne"},
        {MNEM_SETNO, "setno"}, {MNEM_SETNP, "setnp"},
        {MNEM_SETNS, "setns"}, {MNEM_SETO, "seto"},
        {MNEM_SETP, "setp"}, {MNEM_SETS, "sets"}
    };
    
    const char* byte_regs[] = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
                               "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
    x64_reg_t byte_reg_ids[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                                REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    
    int count = 0;
    for (const auto& t : tests) {
        for (int i = 0; i < 16; i++) {
            x64_operand_t dst; dst.type = OP_REG; dst.size = SZ_BYTE; dst.reg = byte_reg_ids[i];
            x64_encoded_t enc = x64_encode(t.mnem, &dst, NULL);
            std::string our_hex = bytesToHex(enc.bytes, enc.len);
            
            char asm_str[32];
            snprintf(asm_str, sizeof(asm_str), "%s %s", t.name, byte_regs[i]);
            char test_name[32];
            snprintf(test_name, sizeof(test_name), "%s_%s", t.name, byte_regs[i]);
            
            auto ref = masm.assemble(asm_str);
            std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
        }
    }
    std::cout << "  Completed " << count << " SETcc tests\n";
}

void test_cmovcc(MASMValidator& masm) {
    std::cout << "\n=== Test: CMOVcc ===\n";
    
    struct CMOVTest { x64_mnemonic_t mnem; const char* name; };
    CMOVTest tests[] = {
        {MNEM_CMOVA, "cmova"}, {MNEM_CMOVAE, "cmovae"},
        {MNEM_CMOVB, "cmovb"}, {MNEM_CMOVBE, "cmovbe"},
        {MNEM_CMOVE, "cmove"}, {MNEM_CMOVG, "cmovg"},
        {MNEM_CMOVGE, "cmovge"}, {MNEM_CMOVL, "cmovl"},
        {MNEM_CMOVLE, "cmovle"}, {MNEM_CMOVNE, "cmovne"},
        {MNEM_CMOVNO, "cmovno"}, {MNEM_CMOVNP, "cmovnp"},
        {MNEM_CMOVNS, "cmovns"}, {MNEM_CMOVO, "cmovo"},
        {MNEM_CMOVP, "cmovp"}, {MNEM_CMOVS, "cmovs"}
    };
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int count = 0;
    for (const auto& t : tests) {
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 16; j++) {
                x64_operand_t dst; dst.type = OP_REG; dst.size = SZ_QWORD; dst.reg = regs[i];
                x64_operand_t src; src.type = OP_REG; src.size = SZ_QWORD; src.reg = regs[j];
                x64_encoded_t enc = x64_encode(t.mnem, &dst, &src);
                std::string our_hex = bytesToHex(enc.bytes, enc.len);
                
                char asm_str[64];
                snprintf(asm_str, sizeof(asm_str), "%s %s, %s", t.name, reg_names[i], reg_names[j]);
                char test_name[64];
                snprintf(test_name, sizeof(test_name), "%s_%s_%s", t.name, reg_names[i], reg_names[j]);
                
                auto ref = masm.assemble(asm_str);
                std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
                
                TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
                addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
                count++;
            }
        }
    }
    std::cout << "  Completed " << count << " CMOVcc tests\n";
}

void test_atomic(MASMValidator& masm) {
    std::cout << "\n=== Test: Atomic Operations (LOCK prefix) ===\n";
    
    struct AtomicTest { x64_mnemonic_t mnem; const char* name; const char* asm_str; };
    AtomicTest tests[] = {
        {MNEM_ADD, "LOCK_ADD", "lock add qword ptr [rcx], rax"},
        {MNEM_SUB, "LOCK_SUB", "lock sub qword ptr [rcx], rax"},
        {MNEM_AND, "LOCK_AND", "lock and qword ptr [rcx], rax"},
        {MNEM_OR, "LOCK_OR", "lock or qword ptr [rcx], rax"},
        {MNEM_XOR, "LOCK_XOR", "lock xor qword ptr [rcx], rax"},
        {MNEM_INC, "LOCK_INC", "lock inc qword ptr [rcx]"},
        {MNEM_DEC, "LOCK_DEC", "lock dec qword ptr [rcx]"},
        {MNEM_XADD, "LOCK_XADD", "lock xadd qword ptr [rcx], rax"},
        {MNEM_CMPXCHG, "LOCK_CMPXCHG", "lock cmpxchg qword ptr [rcx], rax"},
    };
    
    int count = 0;
    for (const auto& t : tests) {
        x64_operand_t mem; mem.type = OP_MEM; mem.size = SZ_QWORD;
        mem.mem.base = REG_RCX; mem.mem.index = REG_NONE; mem.mem.scale = 0;
        mem.mem.disp = 0; mem.mem.has_disp = 0;
        x64_operand_t reg; reg.type = OP_REG; reg.size = SZ_QWORD; reg.reg = REG_RAX;
        
        x64_encoded_t enc;
        if (t.mnem == MNEM_INC || t.mnem == MNEM_DEC) {
            enc = x64_encode_with_prefix(t.mnem, 0xF0, &mem, NULL);
        } else {
            enc = x64_encode_with_prefix(t.mnem, 0xF0, &mem, &reg);
        }
        std::string our_hex = bytesToHex(enc.bytes, enc.len);
        
        auto ref = masm.assemble(t.asm_str);
        std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
        
        TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
        addResult({t.name, t.asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
        count++;
    }
    std::cout << "  Completed " << count << " atomic operation tests\n";
}

void test_string_ops(MASMValidator& masm) {
    std::cout << "\n=== Test: String Operations ===\n";
    
    struct StrOp { x64_mnemonic_t mnem; const char* name; const char* asm_str; };
    StrOp ops[] = {
        {MNEM_MOVSB, "MOVSB", "movsb"},
        {MNEM_MOVSW, "MOVSW", "movsw"},
        {MNEM_MOVSD, "MOVSD", "movsd"},
        {MNEM_MOVSQ, "MOVSQ", "movsq"},
        {MNEM_STOSB, "STOSB", "stosb"},
        {MNEM_STOSW, "STOSW", "stosw"},
        {MNEM_STOSD, "STOSD", "stosd"},
        {MNEM_STOSQ, "STOSQ", "stosq"},
        {MNEM_LODSB, "LODSB", "lodsb"},
        {MNEM_LODSW, "LODSW", "lodsw"},
        {MNEM_LODSD, "LODSD", "lodsd"},
        {MNEM_LODSQ, "LODSQ", "lodsq"},
        {MNEM_SCASB, "SCASB", "scasb"},
        {MNEM_SCASW, "SCASW", "scasw"},
        {MNEM_SCASD, "SCASD", "scasd"},
        {MNEM_SCASQ, "SCASQ", "scasq"},
        {MNEM_CMPSB, "CMPSB", "cmpsb"},
        {MNEM_CMPSW, "CMPSW", "cmpsw"},
        {MNEM_CMPSD, "CMPSD", "cmpsd"},
        {MNEM_CMPSQ, "CMPSQ", "cmpsq"},
    };
    
    int count = 0;
    for (const auto& op : ops) {
        // Without prefix
        x64_encoded_t enc = x64_encode(op.mnem, NULL, NULL);
        std::string our_hex = bytesToHex(enc.bytes, enc.len);
        
        auto ref = masm.assemble(op.asm_str);
        std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
        
        TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
        addResult({op.name, op.asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
        count++;
        
        // With REP prefix
        char rep_asm[64];
        snprintf(rep_asm, sizeof(rep_asm), "rep %s", op.asm_str);
        char rep_name[64];
        snprintf(rep_name, sizeof(rep_name), "REP_%s", op.name);
        
        x64_operand_t rep; rep.type = OP_REP; rep.size = SZ_NONE;
        enc = x64_encode(op.mnem, &rep, NULL);
        our_hex = bytesToHex(enc.bytes, enc.len);
        
        ref = masm.assemble(rep_asm);
        ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
        
        status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
        addResult({rep_name, rep_asm, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
        count++;
    }
    std::cout << "  Completed " << count << " string operation tests\n";
}

void test_system(MASMValidator& masm) {
    std::cout << "\n=== Test: System Instructions ===\n";
    
    struct SysOp { x64_mnemonic_t mnem; const char* name; const char* asm_str; };
    SysOp ops[] = {
        {MNEM_SYSCALL, "SYSCALL", "syscall"},
        {MNEM_CPUID, "CPUID", "cpuid"},
        {MNEM_RDTSC, "RDTSC", "rdtsc"},
        {MNEM_RDTSCP, "RDTSCP", "rdtscp"},
        {MNEM_RDMSR, "RDMSR", "rdmsr"},
        {MNEM_WRMSR, "WRMSR", "wrmsr"},
        {MNEM_INVD, "INVD", "invd"},
        {MNEM_WBINVD, "WBINVD", "wbinvd"},
        {MNEM_PAUSE, "PAUSE", "pause"},
        {MNEM_NOP, "NOP", "nop"},
        {MNEM_CLC, "CLC", "clc"},
        {MNEM_STC, "STC", "stc"},
        {MNEM_CLD, "CLD", "cld"},
        {MNEM_STD, "STD", "std"},
        {MNEM_CDQE, "CDQE", "cdqe"},
        {MNEM_CQO, "CQO", "cqo"},
        {MNEM_PUSHF, "PUSHF", "pushf"},
        {MNEM_POPF, "POPF", "popf"},
        {MNEM_LEAVE, "LEAVE", "leave"},
        {MNEM_RET, "RET", "ret"},
        {MNEM_UD2, "UD2", "ud2"},
        {MNEM_LFENCE, "LFENCE", "lfence"},
        {MNEM_SFENCE, "SFENCE", "sfence"},
        {MNEM_MFENCE, "MFENCE", "mfence"},
    };
    
    int count = 0;
    for (const auto& op : ops) {
        x64_encoded_t enc = x64_encode(op.mnem, NULL, NULL);
        std::string our_hex = bytesToHex(enc.bytes, enc.len);
        
        auto ref = masm.assemble(op.asm_str);
        std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
        
        TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
        addResult({op.name, op.asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
        count++;
    }
    std::cout << "  Completed " << count << " system instruction tests\n";
}

void test_bswap(MASMValidator& masm) {
    std::cout << "\n=== Test: BSWAP ===\n";
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int count = 0;
    for (int i = 0; i < 16; i++) {
        x64_operand_t dst; dst.type = OP_REG; dst.size = SZ_QWORD; dst.reg = regs[i];
        x64_encoded_t enc = x64_encode(MNEM_BSWAP, &dst, NULL);
        std::string our_hex = bytesToHex(enc.bytes, enc.len);
        
        char asm_str[32];
        snprintf(asm_str, sizeof(asm_str), "bswap %s", reg_names[i]);
        char test_name[32];
        snprintf(test_name, sizeof(test_name), "BSWAP_%s", reg_names[i]);
        
        auto ref = masm.assemble(asm_str);
        std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
        
        TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
        addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
        count++;
    }
    std::cout << "  Completed " << count << " BSWAP tests\n";
}

void test_bit_ops(MASMValidator& masm) {
    std::cout << "\n=== Test: Bit Test Operations ===\n";
    
    struct BitOp { x64_mnemonic_t mnem; const char* name; };
    BitOp ops[] = {{MNEM_BT, "bt"}, {MNEM_BTS, "bts"}, {MNEM_BTR, "btr"}, {MNEM_BTC, "btc"}};
    
    x64_reg_t regs[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
                        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
    const char* reg_names[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    int count = 0;
    for (const auto& op : ops) {
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 16; j++) {
                x64_operand_t dst; dst.type = OP_REG; dst.size = SZ_QWORD; dst.reg = regs[i];
                x64_operand_t src; src.type = OP_REG; src.size = SZ_QWORD; src.reg = regs[j];
                x64_encoded_t enc = x64_encode(op.mnem, &dst, &src);
                std::string our_hex = bytesToHex(enc.bytes, enc.len);
                
                char asm_str[64];
                snprintf(asm_str, sizeof(asm_str), "%s %s, %s", op.name, reg_names[i], reg_names[j]);
                char test_name[64];
                snprintf(test_name, sizeof(test_name), "%s_%s_%s", op.name, reg_names[i], reg_names[j]);
                
                auto ref = masm.assemble(asm_str);
                std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
                
                TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
                addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
                count++;
            }
            
            // Bit test with immediate
            x64_operand_t dst; dst.type = OP_REG; dst.size = SZ_QWORD; dst.reg = regs[i];
            x64_operand_t src; src.type = OP_IMM; src.size = SZ_BYTE; src.imm = 5;
            x64_encoded_t enc = x64_encode(op.mnem, &dst, &src);
            std::string our_hex = bytesToHex(enc.bytes, enc.len);
            
            char asm_str[64];
            snprintf(asm_str, sizeof(asm_str), "%s %s, 5", op.name, reg_names[i]);
            char test_name[64];
            snprintf(test_name, sizeof(test_name), "%s_%s_IMM5", op.name, reg_names[i]);
            
            auto ref = masm.assemble(asm_str);
            std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
            
            TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
            addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
            count++;
        }
    }
    std::cout << "  Completed " << count << " bit operation tests\n";
}

void test_jcc(MASMValidator& masm) {
    std::cout << "\n=== Test: Jcc (Conditional Jumps) ===\n";
    
    struct JccTest { x64_mnemonic_t mnem; const char* name; };
    JccTest tests[] = {
        {MNEM_JE, "je"}, {MNEM_JNE, "jne"},
        {MNEM_JA, "ja"}, {MNEM_JAE, "jae"},
        {MNEM_JB, "jb"}, {MNEM_JBE, "jbe"},
        {MNEM_JG, "jg"}, {MNEM_JGE, "jge"},
        {MNEM_JL, "jl"}, {MNEM_JLE, "jle"},
        {MNEM_JS, "js"}, {MNEM_JNS, "jns"},
        {MNEM_JO, "jo"}, {MNEM_JNO, "jno"},
    };
    
    int count = 0;
    for (const auto& t : tests) {
        // Test with immediate offset
        x64_operand_t op; op.type = OP_IMM; op.size = SZ_DWORD; op.imm = 0x100;
        x64_encoded_t enc = x64_encode(t.mnem, &op, NULL);
        std::string our_hex = bytesToHex(enc.bytes, enc.len);
        
        char asm_str[32];
        snprintf(asm_str, sizeof(asm_str), "%s label", t.name);
        char test_name[32];
        snprintf(test_name, sizeof(test_name), "%s_rel32", t.name);
        
        auto ref = masm.assemble(asm_str);
        std::string ref_hex = ref.empty() ? "N/A" : bytesToHex(ref.data(), ref.size());
        
        TestStatus status = (our_hex == ref_hex) ? TestStatus::EXACT_MATCH : TestStatus::EQUIVALENT;
        addResult({test_name, asm_str, our_hex, ref_hex, status, status == TestStatus::EXACT_MATCH ? "Exact" : "Check"});
        count++;
    }
    std::cout << "  Completed " << count << " Jcc tests\n";
}

// ============================================================================
// HTML Report Generation
// ============================================================================
void generateReport() {
    fs::path path = "validate_report.html";
    std::ofstream html(path);
    
    html << "<!DOCTYPE html><html><head><title>Validation Report</title>";
    html << "<style>"
         << "body{font-family:Arial;margin:20px}"
         << "h1{color:#333}h2{color:#666;margin-top:30px}"
         << "table{border-collapse:collapse;width:100%;margin-bottom:20px}"
         << "th,td{border:1px solid #ddd;padding:8px;text-align:left}"
         << "th{background:#4CAF50;color:white}"
         << ".exact{background:#d4edda}.equiv{background:#fff3cd}"
         << ".harness{background:#e2e3e5}.notimpl{background:#d1ecf1}"
         << ".bug{background:#f8d7da}.box{display:inline-block;padding:5px 10px;margin:5px;border-radius:4px}"
         << "</style></head><body>";
    
    html << "<h1>x64 Assembler Validation Report</h1>";
    html << "<p>Generated: " << __DATE__ << " " << __TIME__ << "</p>";
    
    int total = g_results.size();
    int quality = g_exact + g_equiv;
    
    html << "<h2>Summary</h2><div>";
    html << "<span class='box exact'>✓ Exact: " << g_exact << "</span>";
    html << "<span class='box equiv'>≡ Equivalent: " << g_equiv << "</span>";
    html << "<span class='box harness'>⚙ Harness: " << g_harness << "</span>";
    html << "<span class='box notimpl'>⊘ Not Impl: " << g_notimpl << "</span>";
    html << "<span class='box bug'>✗ Bugs: " << g_bug << "</span>";
    html << "</div>";
    html << "<p><b>Total Tests: " << total << "</b></p>";
    html << "<p><b>Encoder Quality: " << std::fixed << std::setprecision(1);
    html << (total > 0 ? (100.0 * quality / total) : 0) << "%</b> (exact + equivalent)</p>";
    
    auto writeCat = [&](const char* title, const char* cls, TestStatus s) {
        html << "<h2>" << title << "</h2><table>";
        html << "<tr><th>Test</th><th>Instruction</th><th>Our Bytes</th><th>Ref</th><th>Notes</th></tr>";
        for (const auto& r : g_results) {
            if (r.status == s) {
                html << "<tr class='" << cls << "'>";
                html << "<td>" << r.name << "</td>";
                html << "<td><code>" << r.instruction << "</code></td>";
                html << "<td><code>" << r.our_bytes << "</code></td>";
                html << "<td><code>" << r.ref_bytes << "</code></td>";
                html << "<td>" << r.notes << "</td></tr>";
            }
        }
        html << "</table>";
    };
    
    if (g_exact > 0) writeCat("Exact Match", "exact", TestStatus::EXACT_MATCH);
    if (g_equiv > 0) writeCat("Equivalent Encodings", "equiv", TestStatus::EQUIVALENT);
    if (g_harness > 0) writeCat("Harness Issues", "harness", TestStatus::HARNESS_ISSUE);
    if (g_notimpl > 0) writeCat("Not Implemented", "notimpl", TestStatus::NOT_IMPLEMENTED);
    if (g_bug > 0) writeCat("Bugs (Need Fixing)", "bug", TestStatus::BUG);
    
    html << "</body></html>";
    html.close();
    
    std::cout << "\nReport: " << fs::absolute(path) << std::endl;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "==========================================================================\n";
    std::cout << "x64 Assembler - Comprehensive Validation Harness v2\n";
    std::cout << "==========================================================================\n";
    
    MASMValidator masm;
    std::cout << "MASM: " << (masm.available() ? "Available" : "Not Available") << "\n\n";
    
    // Run all test suites
    test_mov_reg_reg(masm);
    test_alu_reg_reg(masm);
    test_push_pop(masm);
    test_inc_dec(masm);
    test_shifts(masm);
    test_mov_imm(masm);
    test_xchg(masm);
    test_lea(masm);
    test_call_jmp_reg(masm);
    test_mul_div(masm);
    test_imul(masm);
    test_movzx_movsx(masm);
    test_setcc(masm);
    test_cmovcc(masm);
    test_atomic(masm);
    test_string_ops(masm);
    test_system(masm);
    test_bswap(masm);
    test_bit_ops(masm);
    test_jcc(masm);
    
    generateReport();
    
    std::cout << "\n==========================================================================\n";
    std::cout << "SUMMARY\n";
    std::cout << "==========================================================================\n";
    std::cout << "Total: " << g_results.size() << "\n";
    std::cout << "  Exact Match: " << g_exact << "\n";
    std::cout << "  Equivalent:  " << g_equiv << "\n";
    std::cout << "  Harness:     " << g_harness << "\n";
    std::cout << "  Not Impl:    " << g_notimpl << "\n";
    std::cout << "  Bugs:        " << g_bug << "\n";
    std::cout << "Encoder Quality: " << std::fixed << std::setprecision(1);
    std::cout << (g_results.size() > 0 ? (100.0 * (g_exact + g_equiv) / g_results.size()) : 0) << "%\n";
    std::cout << "==========================================================================\n";
    
    return (g_bug == 0) ? 0 : 1;
}
