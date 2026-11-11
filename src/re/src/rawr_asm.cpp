/**
 * @file rawr_asm.cpp
 * @brief Multi-Architecture Assembler Implementation
 * @description Full implementation using Keystone engine
 * 
 * @version 1.0.0
 */

#include "rawr_asm.hpp"
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace RE {

Assembler::Assembler(const AsmConfig& config)
    : m_handle(nullptr)
    , m_config(config)
    , m_lastError(KS_ERR_OK) {
    Initialize();
}

Assembler::~Assembler() {
    Cleanup();
}

bool Assembler::Initialize() {
    int arch = GetKeystoneArch(m_config.arch);
    int mode = GetKeystoneMode(m_config.arch);
    
    m_lastError = ks_open(static_cast<ks_arch>(arch), static_cast<ks_mode>(mode), &m_handle);
    if (m_lastError != KS_ERR_OK) {
        return false;
    }
    
    ConfigureOptions();
    return true;
}

void Assembler::Cleanup() {
    if (m_handle != nullptr) {
        ks_close(m_handle);
        m_handle = nullptr;
    }
}

void Assembler::ConfigureOptions() {
    if (m_handle == nullptr) return;
    
    // Set syntax
    if (m_config.syntaxIntel) {
        ks_option(m_handle, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
    } else {
        ks_option(m_handle, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
    }
}

bool Assembler::Reconfigure(const AsmConfig& config) {
    Cleanup();
    m_config = config;
    m_symbols.clear();
    return Initialize();
}

AsmResult Assembler::Assemble(const std::string& instruction) {
    AsmResult result;
    
    if (m_handle == nullptr) {
        result.success = false;
        result.errorMessage = "Assembler not initialized";
        return result;
    }
    
    unsigned char* encode = nullptr;
    size_t size = 0;
    size_t stmtCount = 0;
    
    m_lastError = ks_asm(m_handle, instruction.c_str(), m_config.baseAddress, 
                         &encode, &size, &stmtCount);
    
    if (m_lastError != KS_ERR_OK) {
        result.success = false;
        result.errorMessage = GetLastError();
        result.errorLine = 0;
        return result;
    }
    
    result = ProcessResult(encode, size, stmtCount);
    result.address = m_config.baseAddress;
    
    if (encode != nullptr) {
        ks_free(encode);
    }
    
    return result;
}

AsmResult Assembler::Assemble(const std::vector<std::string>& instructions) {
    std::string code;
    for (const auto& inst : instructions) {
        code += inst + "\n";
    }
    return AssembleCode(code);
}

AsmResult Assembler::AssembleCode(const std::string& code) {
    AsmResult result;
    
    if (m_handle == nullptr) {
        result.success = false;
        result.errorMessage = "Assembler not initialized";
        return result;
    }
    
    unsigned char* encode = nullptr;
    size_t size = 0;
    size_t stmtCount = 0;
    
    m_lastError = ks_asm(m_handle, code.c_str(), m_config.baseAddress,
                         &encode, &size, &stmtCount);
    
    if (m_lastError != KS_ERR_OK) {
        result.success = false;
        result.errorMessage = GetLastError();
        result.errorLine = 0;
        return result;
    }
    
    result = ProcessResult(encode, size, stmtCount);
    result.address = m_config.baseAddress;
    
    if (encode != nullptr) {
        ks_free(encode);
    }
    
    return result;
}

AsmResult Assembler::AssembleWithSymbols(
    const std::string& code,
    const std::map<std::string, uint64_t>& symbols) {
    
    // Store symbols
    m_symbols = symbols;
    
    // Process code with symbol substitution
    std::string processedCode = code;
    for (const auto& [name, addr] : symbols) {
        std::string placeholder = name;
        std::ostringstream oss;
        oss << "0x" << std::hex << addr;
        
        // Simple string replacement
        size_t pos = 0;
        while ((pos = processedCode.find(placeholder, pos)) != std::string::npos) {
            processedCode.replace(pos, placeholder.length(), oss.str());
            pos += oss.str().length();
        }
    }
    
    return AssembleCode(processedCode);
}

AsmResult Assembler::ProcessResult(unsigned char* encode, size_t size, size_t stmtCount) {
    AsmResult result;
    result.success = true;
    result.address = m_config.baseAddress;
    result.errorLine = 0;
    
    if (encode != nullptr && size > 0) {
        result.machineCode.resize(size);
        for (size_t i = 0; i < size; i++) {
            result.machineCode[i] = encode[i];
        }
    }
    
    return result;
}

std::string Assembler::GetLastError() const {
    return ks_strerror(m_lastError);
}

std::string Assembler::GetArchitectureName() const {
    return ArchToString(m_config.arch);
}

void Assembler::AddSymbol(const std::string& name, uint64_t address) {
    m_symbols[name] = address;
}

void Assembler::ClearSymbols() {
    m_symbols.clear();
}

// Quick assemble function
AsmResult QuickAssemble(
    Architecture arch,
    const std::string& instruction,
    uint64_t baseAddress) {
    
    AsmConfig config;
    config.arch = arch;
    config.baseAddress = baseAddress;
    
    Assembler asm_(config);
    return asm_.Assemble(instruction);
}

std::string FormatMachineCode(const std::vector<uint8_t>& code) {
    std::ostringstream oss;
    for (size_t i = 0; i < code.size(); i++) {
        if (i > 0) oss << " ";
        oss << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(code[i]);
    }
    return oss.str();
}

std::string FormatMachineCodeWithAddress(
    const std::vector<uint8_t>& code,
    uint64_t address) {
    
    std::ostringstream oss;
    oss << "0x" << std::hex << address << ": ";
    oss << FormatMachineCode(code);
    return oss.str();
}

} // namespace RE
} // namespace RawrXD
