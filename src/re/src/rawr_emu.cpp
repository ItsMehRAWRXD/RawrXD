/**
 * @file rawr_emu.cpp
 * @brief Multi-Architecture Emulator Implementation
 * @description Full implementation using Unicorn engine
 * 
 * @version 1.0.0
 */

#include "rawr_emu.hpp"
#include <sstream>

namespace RawrXD {
namespace RE {

Emulator::Emulator(const EmuConfig& config)
    : m_handle(nullptr)
    , m_config(config)
    , m_lastError(UC_ERR_OK) {
}

Emulator::~Emulator() {
    if (m_handle != nullptr) {
        uc_close(m_handle);
    }
}

bool Emulator::Initialize() {
    int arch = GetUnicornArch(m_config.arch);
    int mode = GetUnicornMode(m_config.arch);
    
    m_lastError = uc_open(static_cast<uc_arch>(arch), static_cast<uc_mode>(mode), &m_handle);
    if (m_lastError != UC_ERR_OK) {
        return false;
    }
    
    // Setup stack
    return SetupStack();
}

bool Emulator::SetupStack() {
    if (m_handle == nullptr) return false;
    
    // Map stack memory
    if (!MapMemory(m_config.stackAddress, m_config.stackSize, MemPermission::READ_WRITE)) {
        return false;
    }
    
    // Set stack pointer to top of stack
    uint64_t sp = m_config.stackAddress + m_config.stackSize - 0x1000;
    return SetStackPointer(sp);
}

bool Emulator::MapMemory(uint64_t address, size_t size, MemPermission perms) {
    if (m_handle == nullptr) return false;
    
    m_lastError = uc_mem_map(m_handle, address, size, static_cast<uint32_t>(perms));
    return m_lastError == UC_ERR_OK;
}

bool Emulator::UnmapMemory(uint64_t address, size_t size) {
    if (m_handle == nullptr) return false;
    
    m_lastError = uc_mem_unmap(m_handle, address, size);
    return m_lastError == UC_ERR_OK;
}

bool Emulator::WriteMemory(uint64_t address, const void* data, size_t size) {
    if (m_handle == nullptr || data == nullptr) return false;
    
    m_lastError = uc_mem_write(m_handle, address, data, size);
    return m_lastError == UC_ERR_OK;
}

bool Emulator::ReadMemory(uint64_t address, void* data, size_t size) {
    if (m_handle == nullptr || data == nullptr) return false;
    
    m_lastError = uc_mem_read(m_handle, address, data, size);
    return m_lastError == UC_ERR_OK;
}

bool Emulator::WriteRegister(uint32_t regId, uint64_t value) {
    if (m_handle == nullptr) return false;
    
    m_lastError = uc_reg_write(m_handle, regId, &value);
    return m_lastError == UC_ERR_OK;
}

bool Emulator::ReadRegister(uint32_t regId, uint64_t& value) {
    if (m_handle == nullptr) return false;
    
    m_lastError = uc_reg_read(m_handle, regId, &value);
    return m_lastError == UC_ERR_OK;
}

uint32_t Emulator::GetInstructionPointerRegId() const {
    switch (m_config.arch) {
        case Architecture::X86_32:
            return UC_X86_REG_EIP;
        case Architecture::X86_64:
            return UC_X86_REG_RIP;
        case Architecture::ARM_32:
        case Architecture::ARM_THUMB:
        case Architecture::ARM_THUMB2:
            return UC_ARM_REG_PC;
        case Architecture::ARM_64:
            return UC_ARM64_REG_PC;
        case Architecture::MIPS_32:
        case Architecture::MIPS_MICRO:
            return UC_MIPS_REG_PC;
        case Architecture::MIPS_64:
            return UC_MIPS_REG_PC;
        case Architecture::RISCV_32:
            return UC_RISCV_REG_PC;
        case Architecture::RISCV_64:
            return UC_RISCV_REG_PC;
        default:
            return 0;
    }
}

uint32_t Emulator::GetStackPointerRegId() const {
    switch (m_config.arch) {
        case Architecture::X86_32:
            return UC_X86_REG_ESP;
        case Architecture::X86_64:
            return UC_X86_REG_RSP;
        case Architecture::ARM_32:
        case Architecture::ARM_THUMB:
        case Architecture::ARM_THUMB2:
            return UC_ARM_REG_SP;
        case Architecture::ARM_64:
            return UC_ARM64_REG_SP;
        case Architecture::MIPS_32:
        case Architecture::MIPS_MICRO:
            return UC_MIPS_REG_SP;
        case Architecture::MIPS_64:
            return UC_MIPS_REG_SP;
        case Architecture::RISCV_32:
            return UC_RISCV_REG_SP;
        case Architecture::RISCV_64:
            return UC_RISCV_REG_SP;
        default:
            return 0;
    }
}

bool Emulator::SetInstructionPointer(uint64_t address) {
    return WriteRegister(GetInstructionPointerRegId(), address);
}

bool Emulator::GetInstructionPointer(uint64_t& address) {
    return ReadRegister(GetInstructionPointerRegId(), address);
}

bool Emulator::SetStackPointer(uint64_t address) {
    return WriteRegister(GetStackPointerRegId(), address);
}

bool Emulator::GetStackPointer(uint64_t& address) {
    return ReadRegister(GetStackPointerRegId(), address);
}

EmuResult Emulator::Emulate(uint64_t begin, uint64_t until, 
                            uint64_t timeout, size_t count) {
    EmuResult result;
    
    if (m_handle == nullptr) {
        result.errorMessage = "Emulator not initialized";
        return result;
    }
    
    m_lastError = uc_emu_start(m_handle, begin, until, timeout, count);
    
    if (m_lastError == UC_ERR_OK) {
        result.success = true;
        GetInstructionPointer(result.exitAddress);
    } else {
        result.success = false;
        result.errorMessage = GetLastError();
    }
    
    return result;
}

void Emulator::Stop() {
    if (m_handle != nullptr) {
        uc_emu_stop(m_handle);
    }
}

std::string Emulator::GetLastError() const {
    return uc_strerror(m_lastError);
}

std::vector<RegInfo> Emulator::GetRegisters() const {
    std::vector<RegInfo> regs;
    
    // Architecture-specific register lists
    switch (m_config.arch) {
        case Architecture::X86_64:
            regs = {
                {"rax", UC_X86_REG_RAX, 64}, {"rbx", UC_X86_REG_RBX, 64},
                {"rcx", UC_X86_REG_RCX, 64}, {"rdx", UC_X86_REG_RDX, 64},
                {"rsi", UC_X86_REG_RSI, 64}, {"rdi", UC_X86_REG_RDI, 64},
                {"rbp", UC_X86_REG_RBP, 64}, {"rsp", UC_X86_REG_RSP, 64},
                {"r8", UC_X86_REG_R8, 64}, {"r9", UC_X86_REG_R9, 64},
                {"r10", UC_X86_REG_R10, 64}, {"r11", UC_X86_REG_R11, 64},
                {"r12", UC_X86_REG_R12, 64}, {"r13", UC_X86_REG_R13, 64},
                {"r14", UC_X86_REG_R14, 64}, {"r15", UC_X86_REG_R15, 64},
                {"rip", UC_X86_REG_RIP, 64}, {"rflags", UC_X86_REG_EFLAGS, 64}
            };
            break;
        case Architecture::X86_32:
            regs = {
                {"eax", UC_X86_REG_EAX, 32}, {"ebx", UC_X86_REG_EBX, 32},
                {"ecx", UC_X86_REG_ECX, 32}, {"edx", UC_X86_REG_EDX, 32},
                {"esi", UC_X86_REG_ESI, 32}, {"edi", UC_X86_REG_EDI, 32},
                {"ebp", UC_X86_REG_EBP, 32}, {"esp", UC_X86_REG_ESP, 32},
                {"eip", UC_X86_REG_EIP, 32}, {"eflags", UC_X86_REG_EFLAGS, 32}
            };
            break;
        case Architecture::ARM_64:
            regs = {
                {"x0", UC_ARM64_REG_X0, 64}, {"x1", UC_ARM64_REG_X1, 64},
                {"x2", UC_ARM64_REG_X2, 64}, {"x3", UC_ARM64_REG_X3, 64},
                {"x4", UC_ARM64_REG_X4, 64}, {"x5", UC_ARM64_REG_X5, 64},
                {"x6", UC_ARM64_REG_X6, 64}, {"x7", UC_ARM64_REG_X7, 64},
                {"x8", UC_ARM64_REG_X8, 64}, {"x9", UC_ARM64_REG_X9, 64},
                {"x10", UC_ARM64_REG_X10, 64}, {"x11", UC_ARM64_REG_X11, 64},
                {"x12", UC_ARM64_REG_X12, 64}, {"x13", UC_ARM64_REG_X13, 64},
                {"x14", UC_ARM64_REG_X14, 64}, {"x15", UC_ARM64_REG_X15, 64},
                {"sp", UC_ARM64_REG_SP, 64}, {"pc", UC_ARM64_REG_PC, 64}
            };
            break;
        default:
            break;
    }
    
    return regs;
}

int Emulator::GetRegisterId(const std::string& name) const {
    auto regs = GetRegisters();
    for (const auto& reg : regs) {
        if (reg.name == name) {
            return reg.id;
        }
    }
    return -1;
}

// Quick emulate function
EmuResult QuickEmulate(
    Architecture arch,
    const uint8_t* code,
    size_t codeSize,
    uint64_t baseAddress,
    size_t maxInstructions) {
    
    EmuResult result;
    
    EmuConfig config;
    config.arch = arch;
    
    Emulator emu(config);
    if (!emu.Initialize()) {
        result.errorMessage = "Failed to initialize emulator";
        return result;
    }
    
    // Map code memory
    size_t mapSize = ((codeSize + 0xFFF) / 0x1000) * 0x1000; // Round up to page
    if (!emu.MapMemory(baseAddress, mapSize, MemPermission::READ_EXEC)) {
        result.errorMessage = "Failed to map code memory";
        return result;
    }
    
    // Write code
    if (!emu.WriteMemory(baseAddress, code, codeSize)) {
        result.errorMessage = "Failed to write code";
        return result;
    }
    
    // Set instruction pointer
    if (!emu.SetInstructionPointer(baseAddress)) {
        result.errorMessage = "Failed to set instruction pointer";
        return result;
    }
    
    // Emulate
    return emu.Emulate(baseAddress, 0, 0, maxInstructions);
}

} // namespace RE
} // namespace RawrXD
