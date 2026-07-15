/**
 * @file rawr_disasm.hpp
 * @brief Multi-Architecture Disassembler Interface
 * @description High-level C++ wrapper around Capstone engine for disassembling
 *              all supported architectures. No stubs - full implementation.
 * 
 * @version 1.0.0
 */

#pragma once

#include "rawr_arch.hpp"

// Conditionally include Capstone
#ifdef HAS_CAPSTONE
#include <capstone/capstone.h>
#endif

#include <vector>
#include <string>
#include <functional>
#include <memory>

namespace RawrXD {
namespace RE {

/**
 * @brief Disassembled instruction structure
 */
struct DisasmInstruction {
    uint64_t address;           ///< Instruction address
    uint16_t size;              ///< Instruction size in bytes
    std::vector<uint8_t> bytes; ///< Raw instruction bytes
    std::string mnemonic;       ///< Instruction mnemonic
    std::string operands;       ///< Instruction operands
    std::string comment;        ///< Optional comment
    bool isBranch;              ///< Is branch instruction
    bool isCall;                ///< Is call instruction
    bool isReturn;              ///< Is return instruction
    bool isConditional;         ///< Is conditional instruction
    uint64_t branchTarget;      ///< Branch target address (if known)
    
    // Architecture-specific details
    Architecture arch;
    uint32_t id;                ///< Capstone instruction ID
    uint8_t groups[8];          ///< Instruction groups
    uint8_t groupsCount;
};

/**
 * @brief Disassembler configuration
 */
struct DisasmConfig {
    Architecture arch;
    ArchFeature features;
    bool detailMode;            ///< Enable detailed disassembly
    bool skipData;              ///< Skip data sections
    bool syntaxIntel;           ///< Use Intel syntax (vs AT&T)
    uint64_t baseAddress;       ///< Base address for disassembly
    
    DisasmConfig() 
        : arch(Architecture::X86_64)
        , features(ArchFeature::NONE)
        , detailMode(true)
        , skipData(false)
        , syntaxIntel(true)
        , baseAddress(0x1000) {}
};

/**
 * @brief Multi-architecture disassembler class
 * 
 * This class provides a unified interface for disassembling all supported
 * architectures using the Capstone engine.
 */
class Disassembler {
public:
    /**
     * @brief Constructor
     * @param config Disassembler configuration
     */
    explicit Disassembler(const DisasmConfig& config = DisasmConfig());
    
    /**
     * @brief Destructor
     */
    ~Disassembler();
    
    /**
     * @brief Disassemble a buffer of machine code
     * @param code Pointer to machine code buffer
     * @param size Size of buffer in bytes
     * @param count Maximum instructions to disassemble (0 = unlimited)
     * @return Vector of disassembled instructions
     */
    std::vector<DisasmInstruction> Disassemble(
        const uint8_t* code, 
        size_t size, 
        size_t count = 0
    );
    
    /**
     * @brief Disassemble a single instruction
     * @param code Pointer to instruction bytes
     * @param size Maximum size of instruction
     * @return Disassembled instruction (empty if invalid)
     */
    DisasmInstruction DisassembleOne(
        const uint8_t* code, 
        size_t size
    );
    
    /**
     * @brief Disassemble with callback for each instruction
     * @param code Pointer to machine code buffer
     * @param size Size of buffer in bytes
     * @param callback Function called for each instruction
     * @return Number of instructions disassembled
     */
    size_t DisassembleCallback(
        const uint8_t* code,
        size_t size,
        std::function<bool(const DisasmInstruction&)> callback
    );
    
    /**
     * @brief Check if disassembler is valid/initialized
     * @return true if ready to use
     */
    bool IsValid() const { return m_handle != 0; }
    
    /**
     * @brief Get last error message
     * @return Error string
     */
    std::string GetLastError() const;
    
    /**
     * @brief Get current configuration
     * @return Configuration reference
     */
    const DisasmConfig& GetConfig() const { return m_config; }
    
    /**
     * @brief Reconfigure for different architecture
     * @param config New configuration
     * @return true if successful
     */
    bool Reconfigure(const DisasmConfig& config);
    
    /**
     * @brief Get architecture name
     * @return Architecture name string
     */
    std::string GetArchitectureName() const;
    
    /**
     * @brief Get instruction name from ID
     * @param id Capstone instruction ID
     * @return Instruction name
     */
    std::string GetInstructionName(uint32_t id) const;
    
    /**
     * @brief Get register name
     * @param regId Capstone register ID
     * @return Register name
     */
    std::string GetRegisterName(uint32_t regId) const;
    
    /**
     * @brief Get group name
     * @param groupId Capstone group ID
     * @return Group name
     */
    std::string GetGroupName(uint32_t groupId) const;

private:
#ifdef HAS_CAPSTONE
    csh m_handle;               ///< Capstone handle
    cs_err m_lastError;         ///< Last error code
#else
    void* m_handle;             ///< Opaque handle (not used without Capstone)
    int m_lastError;              ///< Last error code
#endif
    DisasmConfig m_config;      ///< Current configuration
    
    /**
     * @brief Initialize Capstone engine
     * @return true if successful
     */
    bool Initialize();
    
    /**
     * @brief Close Capstone engine
     */
    void Cleanup();
    
    /**
     * @brief Convert Capstone instruction to our format
     */
#ifdef HAS_CAPSTONE
    DisasmInstruction ConvertInstruction(cs_insn* insn) const;
#else
    DisasmInstruction ConvertInstruction(void* insn) const;
#endif
    
    /**
     * @brief Set Capstone options based on config
     */
    void ConfigureOptions();
};

/**
 * @brief Quick disassemble function (stateless)
 * @param arch Architecture to disassemble
 * @param code Machine code buffer
 * @param size Buffer size
 * @param baseAddress Base address
 * @return Vector of instructions
 */
std::vector<DisasmInstruction> QuickDisassemble(
    Architecture arch,
    const uint8_t* code,
    size_t size,
    uint64_t baseAddress = 0x1000
);

/**
 * @brief Format instruction as string
 * @param insn Instruction to format
 * @return Formatted string (e.g., "mov rax, rbx")
 */
std::string FormatInstruction(const DisasmInstruction& insn);

/**
     * @brief Format instruction with address
     * @param insn Instruction to format
     * @return Formatted string (e.g., "0x1000: mov rax, rbx")
     */
std::string FormatInstructionWithAddress(const DisasmInstruction& insn);

} // namespace RE
} // namespace RawrXD
