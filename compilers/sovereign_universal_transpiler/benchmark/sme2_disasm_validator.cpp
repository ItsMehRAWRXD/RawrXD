// ============================================================================
// benchmark/sme2_disasm_validator.cpp - SME2 Instruction Encoding Validator
// Disassembles and validates generated A64 opcodes against expected encodings
// ============================================================================

#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>

extern "C" {
    uint32_t SME2_Encode_SMSTART_VG4();
    uint32_t SME2_Encode_SMSTOP_VG4();
    uint32_t SME2_Encode_ZERO_VG4(uint32_t mask);
    uint32_t SME2_Encode_LDR_ZT0(uint32_t xn, uint32_t offset);
    uint32_t SME2_Encode_LUTI4_VG4_S(uint32_t zd, uint32_t zn, uint32_t imm2);
    uint32_t SME2_Encode_LUTI2_VG4_S(uint32_t zd, uint32_t zn, uint32_t imm3);
    uint32_t SME2_Encode_FMOPA_VG4_S(uint32_t tile, uint32_t zn, uint32_t zm,
                                      uint32_t pn, uint32_t pm);
}

struct EncodingTest {
    const char* name;
    uint32_t expected;
    uint32_t actual;
    bool pass;
};

static std::string OpcodeToBinary(uint32_t opcode) {
    std::stringstream ss;
    for (int i = 31; i >= 0; --i) {
        ss << ((opcode >> i) & 1);
        if (i % 8 == 0 && i > 0) ss << " ";
    }
    return ss.str();
}

int main() {
    std::cout << "\n";
    std::cout << "=========================================================\n";
    std::cout << "  SME2 Instruction Encoding Validation\n";
    std::cout << "=========================================================\n";

    std::vector<EncodingTest> tests;
    int passed = 0, failed = 0;

    auto check = [&](const char* name, uint32_t expected, uint32_t actual) {
        bool pass = (expected == 0) || (expected == actual);
        tests.push_back({name, expected, actual, pass});
        if (pass) passed++; else failed++;
    };

    // 1. SMSTART / SMSTOP
    check("SMSTART SMZA", 0xD503437F, SME2_Encode_SMSTART_VG4());
    check("SMSTOP SMZA",  0xD503401F, SME2_Encode_SMSTOP_VG4());

    // 2. ZERO { ZA0.S, ZA1.S }
    check("ZERO {ZA0,ZA1}", 0xC0080003, SME2_Encode_ZERO_VG4(3));

    // 3. LDR ZT0, [X0]
    check("LDR ZT0, [X0]", 0xE11F0000, SME2_Encode_LDR_ZT0(0, 0));

    // 4. LUTI4 VG4 (Z4, Z0, imm2=0)
    check("LUTI4 {Z4-Z7}, ZT0, Z0.B, #0", 0xC5080020, SME2_Encode_LUTI4_VG4_S(4, 0, 0));

    // 5. LUTI4 VG4 (Z12, Z0, imm2=1)
    check("LUTI4 {Z12-Z15}, ZT0, Z0.B, #1", 0xC5080021, SME2_Encode_LUTI4_VG4_S(12, 0, 1));

    // 6. LUTI2 VG4 (Z4, Z0, imm3=0)
    check("LUTI2 {Z4-Z7}, ZT0, Z0.B, #0", 0xC5000020, SME2_Encode_LUTI2_VG4_S(4, 0, 0));

    // 7. FMOPA VG4 (ZA0, Z4, Z8, P0, P0)
    check("FMOPA ZA0, P0, P0, Z4-Z7, Z8-Z11", 0x080B0000,
          SME2_Encode_FMOPA_VG4_S(0, 4, 8, 0, 0));

    // 8. FMOPA VG4 (ZA1, Z12, Z8, P0, P0)
    check("FMOPA ZA1, P0, P0, Z12-Z15, Z8-Z11", 0x080B0001,
          SME2_Encode_FMOPA_VG4_S(1, 12, 8, 0, 0));

    // Print results
    std::cout << "\n";
    std::cout << std::left << std::setw(50) << "Instruction"
              << std::right << std::setw(12) << "Expected"
              << std::setw(12) << "Actual"
              << std::setw(10) << "Status" << "\n";
    std::cout << std::string(84, '-') << "\n";

    for (const auto& t : tests) {
        std::cout << std::left << std::setw(50) << t.name
                  << std::right << std::hex
                  << std::setw(12) << t.expected
                  << std::setw(12) << t.actual
                  << std::dec
                  << std::setw(10) << (t.pass ? "PASS" : "FAIL") << "\n";
        if (!t.pass) {
            std::cout << "  Binary: " << OpcodeToBinary(t.actual) << "\n";
        }
    }

    std::cout << "\n";
    std::cout << "=========================================================\n";
    std::cout << "  Encoding Validation Summary\n";
    std::cout << "=========================================================\n";
    std::cout << "  Total:  " << tests.size() << "\n";
    std::cout << "  Passed: " << passed << "\n";
    std::cout << "  Failed: " << failed << "\n";
    std::cout << "  Status: " << (failed == 0 ? "ALL VALID" : "ENCODING ERRORS") << "\n";
    std::cout << "=========================================================\n\n";

    return failed > 0 ? 1 : 0;
}
