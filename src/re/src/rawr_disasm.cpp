/**
 * @file rawr_disasm.cpp
 * @brief Multi-Architecture Disassembler Implementation
 * @description Full implementation using Capstone engine
 * 
 * @version 1.0.0
 */

#include "rawr_disasm.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace RawrXD {
namespace RE {

Disassembler::Disassembler(const DisasmConfig& config)
    : m_handle(0)
    , m_config(config)
    , m_lastError(static_cast<cs_err>(0)) {
    Initialize();
}

Disassembler::~Disassembler() {
    Cleanup();
}

bool Disassembler::Initialize() {
#ifdef HAS_CAPSTONE
    cs_arch arch = static_cast<cs_arch>(GetCapstoneArch(m_config.arch));
    cs_mode mode = static_cast<cs_mode>(GetCapstoneMode(m_config.arch));

    // Add feature flags to mode
    if (hasFeature(m_config.features, ArchFeature::ARM_VFPv3) ||
        hasFeature(m_config.features, ArchFeature::ARM_VFPv4)) {
        mode = static_cast<cs_mode>(static_cast<int>(mode) | CS_MODE_VFP3);
    }

    m_lastError = cs_open(arch, mode, &m_handle);
    if (m_lastError != CS_ERR_OK) {
        return false;
    }

    ConfigureOptions();
    return true;
#else
    (void)m_config;
    m_lastError = static_cast<cs_err>(-1);
    return false;
#endif
}

void Disassembler::Cleanup() {
#ifdef HAS_CAPSTONE
    if (m_handle != 0) {
        cs_close(&m_handle);
        m_handle = 0;
    }
#else
    m_handle = 0;
#endif
}
}

void Disassembler::ConfigureOptions() {
    if (m_handle == 0) return;
    
    // Enable detailed disassembly
    if (m_config.detailMode) {
        cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
    } else {
        cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_OFF);
    }
    
    // Set syntax
    if (m_config.syntaxIntel) {
        cs_option(m_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    } else {
        cs_option(m_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    }
    
    // Skip data
    if (m_config.skipData) {
        cs_option(m_handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    } else {
        cs_option(m_handle, CS_OPT_SKIPDATA, CS_OPT_OFF);
    }
}

bool Disassembler::Reconfigure(const DisasmConfig& config) {
    Cleanup();
    m_config = config;
    return Initialize();
}

std::vector<DisasmInstruction> Disassembler::Disassemble(
    const uint8_t* code, 
    size_t size, 
    size_t count) {
    
    std::vector<DisasmInstruction> result;
    
    if (m_handle == 0 || code == nullptr || size == 0) {
        return result;
    }
    
    cs_insn* insn = nullptr;
    size_t insnCount = cs_disasm(m_handle, code, size, m_config.baseAddress, count, &insn);
    
    if (insnCount == 0) {
        m_lastError = cs_errno(m_handle);
        return result;
    }
    
    result.reserve(insnCount);
    for (size_t i = 0; i < insnCount; i++) {
        result.push_back(ConvertInstruction(&insn[i]));
    }
    
    cs_free(insn, insnCount);
    return result;
}

DisasmInstruction Disassembler::DisassembleOne(const uint8_t* code, size_t size) {
    DisasmInstruction result;
    
    if (m_handle == 0 || code == nullptr || size == 0) {
        return result;
    }
    
    cs_insn* insn = nullptr;
    size_t count = cs_disasm(m_handle, code, size, m_config.baseAddress, 1, &insn);
    
    if (count > 0) {
        result = ConvertInstruction(&insn[0]);
        cs_free(insn, count);
    } else {
        m_lastError = cs_errno(m_handle);
    }
    
    return result;
}

size_t Disassembler::DisassembleCallback(
    const uint8_t* code,
    size_t size,
    std::function<bool(const DisasmInstruction&)> callback) {
    
    if (m_handle == 0 || code == nullptr || size == 0) {
        return 0;
    }
    
    cs_insn* insn = nullptr;
    size_t insnCount = cs_disasm(m_handle, code, size, m_config.baseAddress, 0, &insn);
    
    if (insnCount == 0) {
        m_lastError = cs_errno(m_handle);
        return 0;
    }
    
    size_t processed = 0;
    for (size_t i = 0; i < insnCount; i++) {
        DisasmInstruction inst = ConvertInstruction(&insn[i]);
        if (!callback(inst)) {
            break;
        }
        processed++;
    }
    
    cs_free(insn, insnCount);
    return processed;
}

DisasmInstruction Disassembler::ConvertInstruction(cs_insn* insn) const {
    DisasmInstruction result;
    
    result.address = insn->address;
    result.size = insn->size;
    result.mnemonic = insn->mnemonic;
    result.operands = insn->op_str;
    result.arch = m_config.arch;
    result.id = insn->id;
    
    // Copy bytes
    result.bytes.resize(insn->size);
    for (uint16_t i = 0; i < insn->size; i++) {
        result.bytes[i] = insn->bytes[i];
    }
    
    // Analyze instruction type
    result.isBranch = false;
    result.isCall = false;
    result.isReturn = false;
    result.isConditional = false;
    result.branchTarget = 0;
    
    if (insn->detail != nullptr) {
        result.groupsCount = insn->detail->groups_count;
        for (uint8_t i = 0; i < result.groupsCount && i < 8; i++) {
            result.groups[i] = insn->detail->groups[i];
            
            // Check for branch/call/return groups
            if (insn->detail->groups[i] == CS_GRP_JUMP) {
                result.isBranch = true;
            } else if (insn->detail->groups[i] == CS_GRP_CALL) {
                result.isCall = true;
            } else if (insn->detail->groups[i] == CS_GRP_RET) {
                result.isReturn = true;
            } else if (insn->detail->groups[i] == CS_GRP_BRANCH_RELATIVE) {
                result.isBranch = true;
            }
        }
        
        // Check for conditional branches
        for (uint8_t i = 0; i < insn->detail->groups_count; i++) {
            // This is architecture-specific - would need per-arch handling
            // For now, check common conditional mnemonics
            std::string mnem = result.mnemonic;
            if (mnem.find("j") == 0 && mnem != "jmp" && mnem != "js") {
                result.isConditional = true;
            }
        }
    }
    
    return result;
}

std::string Disassembler::GetLastError() const {
    return cs_strerror(m_lastError);
}

std::string Disassembler::GetArchitectureName() const {
    return ArchToString(m_config.arch);
}

std::string Disassembler::GetInstructionName(uint32_t id) const {
    if (m_handle == 0) return "";
    return cs_insn_name(m_handle, id);
}

std::string Disassembler::GetRegisterName(uint32_t regId) const {
    if (m_handle == 0) return "";
    return cs_reg_name(m_handle, regId);
}

std::string Disassembler::GetGroupName(uint32_t groupId) const {
    if (m_handle == 0) return "";
    return cs_group_name(m_handle, groupId);
}

// Quick disassemble function
std::vector<DisasmInstruction> QuickDisassemble(
    Architecture arch,
    const uint8_t* code,
    size_t size,
    uint64_t baseAddress) {
    
    DisasmConfig config;
    config.arch = arch;
    config.baseAddress = baseAddress;
    
    Disassembler disasm(config);
    return disasm.Disassemble(code, size);
}

std::string FormatInstruction(const DisasmInstruction& insn) {
    std::string result = insn.mnemonic;
    if (!insn.operands.empty()) {
        result += " " + insn.operands;
    }
    return result;
}

std::string FormatInstructionWithAddress(const DisasmInstruction& insn) {
    std::ostringstream oss;
    oss << "0x" << std::hex << insn.address << ": ";
    oss <> insn.mnemonic;
    if (!insn.operands.empty()) {
        oss << " " << insn.operands;
    }
    return oss.str();
}

} // namespace RE
} // namespace RawrXD
