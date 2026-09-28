// ============================================================================
// ide_toolchain_gate.cpp — IDE-native toolchain gate (RAWRXD_WIN32IDE_TOOLCHAIN_001)
// ============================================================================
// Inlines the same verification logic as native_toolchain_cert.cpp but runs
// inside the shipping RawrXD-Win32IDE process via Build -> Native Compile Test.
// Zero external tools. Zero stubs.
// ============================================================================

#include "ide_toolchain_gate.hpp"

#include "rawr_backend_types.hpp"
#include "InstructionEncoderX64.hpp"
#include "RawrCOFFWriter.hpp"
#include "RawrPE64Linker.hpp"
#include "JITAssembler.hpp"

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <string>
#include <fstream>

using namespace RawrXD::Backend;

namespace RawrXD::IDE {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static bool writeFile(const std::string& path, const std::vector<uint8_t>& data)
{
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    return ofs.good();
}

// ---------------------------------------------------------------------------
// JIT Gate Tests
// ---------------------------------------------------------------------------
static bool jitGateReturnConstant()
{
    JITAssembler jit;
    InstructionIR mov;
    mov.mnemonic = Mnemonic::MOV;
    mov.operands.push_back(Operand::fromReg(Register::EAX));
    mov.operands.push_back(Operand::fromImm(Immediate{42}));
    jit.emit(mov);

    InstructionIR ret;
    ret.mnemonic = Mnemonic::RET;
    jit.emit(ret);

    auto fn = jit.finalize();
    if (!fn.entryAddr) return false;
    int result = fn.call<int>();
    return result == 42;
}

static bool jitGateIntegerAdd()
{
    JITAssembler jit;
    InstructionIR mov;
    mov.mnemonic = Mnemonic::MOV;
    mov.operands.push_back(Operand::fromReg(Register::EAX));
    mov.operands.push_back(Operand::fromReg(Register::ECX));
    jit.emit(mov);

    InstructionIR add;
    add.mnemonic = Mnemonic::ADD;
    add.operands.push_back(Operand::fromReg(Register::EAX));
    add.operands.push_back(Operand::fromReg(Register::EDX));
    jit.emit(add);

    InstructionIR ret;
    ret.mnemonic = Mnemonic::RET;
    jit.emit(ret);

    auto fn = jit.finalize();
    if (!fn.entryAddr) return false;
    int result = fn.call<int>(7, 5);
    return result == 12;
}

static bool jitGateConditionalBranch()
{
    JITAssembler jit;
    uint32_t lblZero = jit.label("zero");

    InstructionIR cmp;
    cmp.mnemonic = Mnemonic::CMP;
    cmp.operands.push_back(Operand::fromReg(Register::ECX));
    cmp.operands.push_back(Operand::fromImm(Immediate{5}));
    jit.emit(cmp);

    InstructionIR jne;
    jne.mnemonic = Mnemonic::JCC;
    jne.cc = ConditionCode::NE;
    jne.operands.push_back(Operand::fromLabel(lblZero));
    jit.emit(jne);

    InstructionIR mov1;
    mov1.mnemonic = Mnemonic::MOV;
    mov1.operands.push_back(Operand::fromReg(Register::EAX));
    mov1.operands.push_back(Operand::fromImm(Immediate{1}));
    jit.emit(mov1);

    InstructionIR ret1;
    ret1.mnemonic = Mnemonic::RET;
    jit.emit(ret1);

    jit.bind(lblZero);
    InstructionIR mov0;
    mov0.mnemonic = Mnemonic::MOV;
    mov0.operands.push_back(Operand::fromReg(Register::EAX));
    mov0.operands.push_back(Operand::fromImm(Immediate{0}));
    jit.emit(mov0);

    InstructionIR ret0;
    ret0.mnemonic = Mnemonic::RET;
    jit.emit(ret0);

    auto fn = jit.finalize();
    if (!fn.entryAddr) return false;
    return fn.call<int>(5) == 1 && fn.call<int>(3) == 0;
}

static bool jitGateLoop()
{
    JITAssembler jit;
    uint32_t lblLoop = jit.label("loop");

    InstructionIR xorinst;
    xorinst.mnemonic = Mnemonic::XOR;
    xorinst.operands.push_back(Operand::fromReg(Register::EAX));
    xorinst.operands.push_back(Operand::fromReg(Register::EAX));
    jit.emit(xorinst);

    jit.bind(lblLoop);
    InstructionIR add;
    add.mnemonic = Mnemonic::ADD;
    add.operands.push_back(Operand::fromReg(Register::EAX));
    add.operands.push_back(Operand::fromReg(Register::ECX));
    jit.emit(add);

    InstructionIR dec;
    dec.mnemonic = Mnemonic::DEC;
    dec.operands.push_back(Operand::fromReg(Register::ECX));
    jit.emit(dec);

    InstructionIR jnz;
    jnz.mnemonic = Mnemonic::JCC;
    jnz.cc = ConditionCode::NZ;
    jnz.operands.push_back(Operand::fromLabel(lblLoop));
    jit.emit(jnz);

    InstructionIR ret;
    ret.mnemonic = Mnemonic::RET;
    jit.emit(ret);

    auto fn = jit.finalize();
    if (!fn.entryAddr) return false;
    return fn.call<int>(5) == 15;
}

static bool runJITGates()
{
    bool ok = true;
    if (!jitGateReturnConstant()) ok = false;
    if (!jitGateIntegerAdd())     ok = false;
    if (!jitGateConditionalBranch()) ok = false;
    if (!jitGateLoop())           ok = false;
    return ok;
}

// ---------------------------------------------------------------------------
// COFF Writer Test
// ---------------------------------------------------------------------------
static bool runCOFFTest()
{
    RawrCOFFWriter coff;
    uint32_t textSec = coff.addSection(".text", 0x00000020u | 0x20000000u | 0x40000000u);
    uint8_t code[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };
    coff.appendSectionData(textSec, code, sizeof(code));

    uint32_t sym = coff.addSymbol("_start", static_cast<int16_t>(textSec + 1), 0, 2);
    coff.addRelocation(textSec, 1, sym, IMAGE_REL_AMD64_REL32);

    std::vector<uint8_t> data = coff.serialize();
    if (data.size() < 24) return false;
    uint16_t machine = *reinterpret_cast<const uint16_t*>(data.data());
    return machine == 0x8664;
}

// ---------------------------------------------------------------------------
// PE64 Linker Test + hello.exe generation
// ---------------------------------------------------------------------------
static bool runPE64Test(std::string& outExePath)
{
    RawrPE64Linker linker;
    linker.setImageBase(0x140000000ULL);

    uint32_t textIdx = linker.addSection(".text",
        RawrPE64Linker::IMAGE_SCN_CNT_CODE |
        RawrPE64Linker::IMAGE_SCN_MEM_EXECUTE |
        RawrPE64Linker::IMAGE_SCN_MEM_READ);

    linker.addImport({ "kernel32.dll", { "GetStdHandle", "WriteConsoleA", "ExitProcess" } });

    uint8_t code[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };
    linker.appendSectionData(textIdx, code, sizeof(code));
    linker.setEntryPoint(textIdx, 0);

    std::vector<uint8_t> pe = linker.link();
    if (pe.size() < 128) return false;
    if (pe[0] != 'M' || pe[1] != 'Z') return false;
    uint32_t peOff = *reinterpret_cast<const uint32_t*>(pe.data() + 0x3C);
    if (peOff + 4 > pe.size() || pe[peOff] != 'P' || pe[peOff + 1] != 'E') return false;

    outExePath = "hello.exe";
    return writeFile(outExePath, pe);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
ToolchainResult runNativeToolchainGate()
{
    ToolchainResult r;
    r.jitOk = runJITGates();
    r.coffOk = runCOFFTest();
    r.peOk = runPE64Test(r.exePath);

    if (r.peOk && !r.exePath.empty()) {
        int ret = std::system(r.exePath.c_str());
        r.helloRunOk = (ret == 0);
    }

    return r;
}

} // namespace RawrXD::IDE
