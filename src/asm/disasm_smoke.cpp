// ============================================================================
// disasm_smoke.cpp
// Positive and negative tests for RawrXD_Disasm_Kernel decoder.
// Run: cl.exe /EHsc /std:c++20 /O2 disasm_smoke.cpp RawrXD_Disasm_Kernel.cpp
// ============================================================================

#include "RawrXD_Disasm_Kernel.hpp"
#include "../../~dev/rawrxd/src/reverse_engineering/RawrCodex_Multi_v2.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

static int g_tests = 0;
static int g_passed = 0;
static int g_failed = 0;

#define TEST(name)                                                              \
    do {                                                                        \
        ++g_tests;                                                              \
        printf("[%d] %s ... ", g_tests, name);                                  \
        fflush(stdout);                                                         \
    } while (0)

#define PASS()                                                                  \
    do {                                                                        \
        ++g_passed;                                                             \
        printf("PASS\n");                                                       \
    } while (0)

#define FAIL(msg)                                                               \
    do {                                                                        \
        ++g_failed;                                                             \
        printf("FAIL: %s\n", msg);                                              \
    } while (0)

#define ASSERT(cond, msg)                                                       \
    do {                                                                        \
        if (!(cond)) { FAIL(msg); return; }                                     \
    } while (0)

// ---- Helper: build a byte vector from hex string --------------------------

static std::vector<std::uint8_t> hexBytes(const char* hex) {
    std::vector<std::uint8_t> out;
    for (size_t i = 0; hex[i]; ) {
        // Skip whitespace
        if (hex[i] == ' ' || hex[i] == '\t' || hex[i] == '\n' || hex[i] == '\r') {
            ++i;
            continue;
        }
        if (!hex[i+1]) break;
        unsigned int v = 0;
        for (int j = 0; j < 2; ++j) {
            char c = hex[i+j];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= c - '0';
            else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
        }
        out.push_back(static_cast<std::uint8_t>(v));
        i += 2;
    }
    return out;
}

// ---- Tests ----------------------------------------------------------------

static void testNOP() {
    TEST("NOP 0x90");
    auto bytes = hexBytes("90");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x1000);
    ASSERT(ins.has_value(), "decode failed");
    ASSERT(ins->mnemonic == "nop", "expected nop");
    ASSERT(ins->length == 1, "expected length 1");
    ASSERT(ins->address == 0x1000, "expected address 0x1000");
    PASS();
}

static void testINT3() {
    TEST("INT3 0xCC");
    auto bytes = hexBytes("CC");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x2000);
    ASSERT(ins.has_value(), "decode failed");
    ASSERT(ins->mnemonic == "int3", "expected int3");
    ASSERT(ins->length == 1, "expected length 1");
    PASS();
}

static void testRET() {
    TEST("RET 0xC3");
    auto bytes = hexBytes("C3");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x3000);
    ASSERT(ins.has_value(), "decode failed");
    ASSERT(ins->mnemonic == "ret", "expected ret");
    ASSERT(ins->isRet, "expected isRet");
    ASSERT(ins->length == 1, "expected length 1");
    PASS();
}

static void testPUSH_RAX() {
    TEST("PUSH rax 0x50");
    auto bytes = hexBytes("50");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x4000);
    ASSERT(ins.has_value(), "decode failed");
    ASSERT(ins->mnemonic == "push", "expected push");
    ASSERT(ins->operands == "rax", "expected rax operand");
    PASS();
}

static void testPUSH_R15() {
    TEST("PUSH r15 (REX.B + 0x57) 0x41 0x57");
    auto bytes = hexBytes("4157");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x4000);
    ASSERT(ins.has_value(), "decode failed");
    ASSERT(ins->mnemonic == "push", "expected push");
    ASSERT(ins->operands == "r15", "expected r15 operand");
    PASS();
}

static void testPOP_RCX() {
    TEST("POP rcx 0x59");
    auto bytes = hexBytes("59");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x4000);
    ASSERT(ins.has_value(), "decode failed");
    ASSERT(ins->mnemonic == "pop", "expected pop");
    ASSERT(ins->operands == "rcx", "expected rcx operand");
    PASS();
}

static void testMOV_RAX_IMM64() {
    TEST("MOV rax, imm64 0x48 0xB8 ...");
    auto bytes = hexBytes("48B80102030405060708");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x5000);
    ASSERT(ins.has_value(), "decode failed");
    ASSERT(ins->mnemonic == "mov", "expected mov");
    ASSERT(ins->length == 10, "expected length 10");
    ASSERT(ins->operands.find("rax") != std::string::npos, "expected rax");
    PASS();
}

static void testJMP_REL8() {
    TEST("JMP rel8 0xEB 0x05");
    auto bytes = hexBytes("EB05");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x1000);
    ASSERT(ins.has_value(), "decode failed");
    ASSERT(ins->mnemonic == "jmp", "expected jmp");
    ASSERT(ins->isBranch, "expected isBranch");
    ASSERT(ins->branchTarget.has_value(), "expected branch target");
    ASSERT(*ins->branchTarget == 0x1000 + 2 + 5, "expected target 0x1007");
    PASS();
}

static void testJCC_REL8() {
    TEST("JZ rel8 0x74 0x0A");
    auto bytes = hexBytes("740A");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x1000);
    ASSERT(ins.has_value(), "decode failed");
    ASSERT(ins->mnemonic == "jz", "expected jz");
    ASSERT(ins->isConditionalBranch, "expected isConditionalBranch");
    ASSERT(*ins->branchTarget == 0x1000 + 2 + 10, "expected target 0x100C");
    PASS();
}

static void testJCC_REL32() {
    TEST("JNZ rel32 0x0F 0x85 ...");
    auto bytes = hexBytes("0F8501020304");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x2000);
    ASSERT(ins.has_value(), "decode failed");
    ASSERT(ins->mnemonic == "jnz", "expected jnz");
    ASSERT(ins->isConditionalBranch, "expected isConditionalBranch");
    // target = 0x2000 + 6 + 0x04030201
    std::int64_t expected = 0x2000 + 6 + 0x04030201;
    ASSERT(*ins->branchTarget == expected, "expected target 0x04050201");
    PASS();
}

static void testCALL_REL32() {
    TEST("CALL rel32 0xE8 ...");
    auto bytes = hexBytes("E801000000");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x3000);
    ASSERT(ins.has_value(), "decode failed");
    ASSERT(ins->mnemonic == "call", "expected call");
    ASSERT(ins->isCall, "expected isCall");
    ASSERT(*ins->branchTarget == 0x3000 + 5 + 1, "expected target 0x3006");
    PASS();
}

static void testMOV_R64_RM64() {
    TEST("MOV rax, [rcx] 0x48 0x8B 0x01");
    auto bytes = hexBytes("488B01");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x4000);
    ASSERT(ins.has_value(), "decode failed");
    ASSERT(ins->mnemonic == "mov", "expected mov");
    ASSERT(ins->operands == "rax, [rcx]", "expected rax, [rcx]");
    PASS();
}

static void testMOV_RM64_R64() {
    TEST("MOV [rcx], rax 0x48 0x89 0x01");
    auto bytes = hexBytes("488901");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x4000);
    ASSERT(ins.has_value(), "decode failed");
    ASSERT(ins->mnemonic == "mov", "expected mov");
    ASSERT(ins->operands == "[rcx], rax", "expected [rcx], rax");
    PASS();
}

static void testTruncated() {
    TEST("Truncated MOV rax, imm64 (missing bytes)");
    auto bytes = hexBytes("48B80102"); // only 4 bytes, need 10
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x1000);
    ASSERT(!ins.has_value(), "expected decode failure for truncated");
    PASS();
}

static void testUnsupported() {
    TEST("Unsupported opcode 0x0F 0x0B (UD2)");
    auto bytes = hexBytes("0F0B");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x1000);
    ASSERT(!ins.has_value(), "expected decode failure for UD2");
    PASS();
}

static void testEmptyInput() {
    TEST("Empty input");
    auto ins = RawrXD::Disasm::decodeInstruction(nullptr, 0, 0x1000);
    ASSERT(!ins.has_value(), "expected decode failure for empty");
    PASS();
}

static void testDecodeBuffer() {
    TEST("DecodeBuffer: NOP INT3 RET");
    auto bytes = hexBytes("90CCC3");
    auto res = RawrXD::Disasm::decodeBuffer(bytes.data(), bytes.data() + bytes.size(), 0x1000);
    ASSERT(!res.error.has_value(), "expected no error");
    ASSERT(res.instructions.size() == 3, "expected 3 instructions");
    ASSERT(res.bytesConsumed == 3, "expected 3 bytes consumed");
    PASS();
}

static void testDecodeBufferStopOnUnsupported() {
    TEST("DecodeBuffer stops at unsupported");
    auto bytes = hexBytes("90 0F0B C3");
    auto res = RawrXD::Disasm::decodeBuffer(bytes.data(), bytes.data() + bytes.size(), 0x1000);
    ASSERT(res.error.has_value(), "expected error");
    ASSERT(res.instructions.size() == 1, "expected 1 instruction before failure");
    ASSERT(res.bytesConsumed == 1, "expected 1 byte consumed");
    PASS();
}

static void testDisassembleString() {
    TEST("disassemble() output");
    auto bytes = hexBytes("90 C3 CC");
    std::string out = RawrXD::Disasm::disassemble(bytes.data(), bytes.data() + bytes.size(), 0x1000);
    ASSERT(out.find("nop") != std::string::npos, "expected nop in output");
    ASSERT(out.find("ret") != std::string::npos, "expected ret in output");
    ASSERT(out.find("int3") != std::string::npos, "expected int3 in output");
    ASSERT(out.find("0000000000001000") != std::string::npos, "expected address 0x1000");
    PASS();
}

static void testIsSupportedOpcode() {
    TEST("isSupportedOpcode");
    ASSERT(RawrXD::Disasm::isSupportedOpcode(0x90), "0x90 should be supported");
    ASSERT(RawrXD::Disasm::isSupportedOpcode(0xC3), "0xC3 should be supported");
    ASSERT(RawrXD::Disasm::isSupportedOpcode(0xEB), "0xEB should be supported");
    ASSERT(RawrXD::Disasm::isSupportedOpcode(0xE8), "0xE8 should be supported");
    ASSERT(!RawrXD::Disasm::isSupportedOpcode(0x0B), "0x0B should not be supported alone");
    PASS();
}

static void testInstructionLength() {
    TEST("instructionLength");
    auto bytes = hexBytes("488B01");
    auto len = RawrXD::Disasm::instructionLength(bytes.data(), bytes.size());
    ASSERT(len.has_value(), "expected length");
    ASSERT(*len == 3, "expected length 3");
    PASS();
}

static void testSubRSP_imm8() {
    TEST("SUB rsp, 0x20 (0x83 Group 1 /5) 48 83 EC 20");
    auto bytes = hexBytes("4883EC20");
    auto ins = RawrXD::Disasm::decodeInstruction(bytes.data(), bytes.size(), 0x1000);
    ASSERT(ins.has_value(), "decode failed");
    ASSERT(ins->mnemonic == "sub", "expected sub, got: " + ins->mnemonic);
    ASSERT(ins->length == 4, "expected length 4");
    ASSERT(ins->operands.find("rsp") != std::string::npos, "expected rsp operand");
    ASSERT(ins->operands.find("32") != std::string::npos, "expected imm 32 (0x20)");
    PASS();
}

static void testX86_NOP() {
    TEST("X86 NOP via ReferenceDecoder_Decode");
    // Test that X86_32 architecture is accepted (not INVALID_ARCH)
    auto bytes = hexBytes("90");
    DecodedInstruction instr;
    memset(&instr, 0, sizeof(instr));
    DecodeStatus status = ReferenceDecoder_Decode(ArchType::X86_32, bytes.data(), bytes.size(), &instr);
    ASSERT(status == DecodeStatus::SUCCESS, "expected SUCCESS for x86 NOP");
    ASSERT(instr.raw.arch == ArchType::X86_32, "expected arch X86_32");
    PASS();
}

static void testX64_NOP() {
    TEST("X64 NOP via ReferenceDecoder_Decode");
    auto bytes = hexBytes("90");
    DecodedInstruction instr;
    memset(&instr, 0, sizeof(instr));
    DecodeStatus status = ReferenceDecoder_Decode(ArchType::X86_64, bytes.data(), bytes.size(), &instr);
    ASSERT(status == DecodeStatus::SUCCESS, "expected SUCCESS for x64 NOP");
    ASSERT(instr.raw.arch == ArchType::X86_64, "expected arch X86_64");
    ASSERT(strcmp(instr.cachedMnemonic, "nop") == 0, "expected mnemonic nop");
    PASS();
}

static void testInvalidArchARM() {
    TEST("ARM64 rejected (INVALID_ARCH)");
    auto bytes = hexBytes("90");
    DecodedInstruction instr;
    memset(&instr, 0, sizeof(instr));
    DecodeStatus status = ReferenceDecoder_Decode(ArchType::ARM_64, bytes.data(), bytes.size(), &instr);
    ASSERT(status == DecodeStatus::ERROR_INVALID_ARCH, "expected INVALID_ARCH for ARM64");
    PASS();
}

// ---- Main -----------------------------------------------------------------

int main() {
    printf("RawrXD Disasm Kernel Smoke Test\n");
    printf("===============================\n\n");

    testNOP();
    testINT3();
    testRET();
    testPUSH_RAX();
    testPUSH_R15();
    testPOP_RCX();
    testMOV_RAX_IMM64();
    testJMP_REL8();
    testJCC_REL8();
    testJCC_REL32();
    testCALL_REL32();
    testMOV_R64_RM64();
    testMOV_RM64_R64();
    testTruncated();
    testUnsupported();
    testEmptyInput();
    testDecodeBuffer();
    testDecodeBufferStopOnUnsupported();
    testDisassembleString();
    testIsSupportedOpcode();
    testInstructionLength();
    testSubRSP_imm8();
    testX86_NOP();
    testX64_NOP();
    testInvalidArchARM();

    printf("\n===============================\n");
    printf("Tests: %d  Passed: %d  Failed: %d\n", g_tests, g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
