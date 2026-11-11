/**
 * @file rawr_asm.hpp
 * @brief Multi-Architecture Assembler Interface
 * @description High-level C++ wrapper around Keystone engine for assembling
 *              all supported architectures. No stubs - full implementation.
 * 
 * @version 1.0.0
 */

#pragma once

#include "rawr_arch.hpp"

// Conditionally include Keystone
#ifdef HAS_KEYSTONE
#include <keystone/keystone.h>
#endif

#include <vector>
#include <string>
#include <functional>
#include <memory>

namespace RawrXD {
namespace RE {

/**
 * @brief Assembly result structure
 */
struct AsmResult {
    bool success;                       ///< Assembly succeeded
    std::vector<uint8_t> machineCode; ///< Generated machine code
    uint64_t address;                   ///< Base address
    std::string errorMessage;           ///< Error message (if failed)
    size_t errorLine;                   ///< Line number of error (0-based)
};

/**
 * @brief Assembler configuration
 */
struct AsmConfig {
    Architecture arch;
    ArchFeature features;
    uint64_t baseAddress;       ///< Base address for assembly
    bool syntaxIntel;           ///< Use Intel syntax (vs AT&T)
    bool resolveSymbols;        ///< Resolve symbolic references
    
    AsmConfig()
        : arch(Architecture::X86_64)
        , features(ArchFeature::NONE)
        , baseAddress(0x1000)
        , syntaxIntel(true)
        , resolveSymbols(true) {}
};

/**
 * @brief Multi-architecture assembler class
 * 
 * This class provides a unified interface for assembling all supported
 * architectures using the Keystone engine.
 */
class Assembler {
public:
    /**
     * @brief Constructor
     * @param config Assembler configuration
     */
    explicit Assembler(const AsmConfig& config = AsmConfig());
    
    /**
     * @brief Destructor
     */
    ~Assembler();
    
    /**
     * @brief Assemble a single instruction
     * @param instruction Assembly instruction string (e.g., "mov rax, rbx")
     * @return Assembly result
     */
    AsmResult Assemble(const std::string& instruction);
    
    /**
     * @brief Assemble multiple instructions
     * @param instructions Vector of instruction strings
     * @return Assembly result
     */
    AsmResult Assemble(const std::vector<std::string>& instructions);
    
    /**
     * @brief Assemble from multi-line string
     * @param code Assembly code (can contain newlines)
     * @return Assembly result
     */
    AsmResult AssembleCode(const std::string& code);
    
    /**
     * @brief Assemble with symbol resolution
     * @param code Assembly code
     * @param symbols Symbol table (name -> address)
     * @return Assembly result
     */
    AsmResult AssembleWithSymbols(
        const std::string& code,
        const std::map<std::string, uint64_t>& symbols
    );
    
    /**
     * @brief Check if assembler is valid/initialized
     * @return true if ready to use
     */
    bool IsValid() const { return m_handle != nullptr; }
    
    /**
     * @brief Get last error message
     * @return Error string
     */
    std::string GetLastError() const;
    
    /**
     * @brief Get current configuration
     * @return Configuration reference
     */
    const AsmConfig& GetConfig() const { return m_config; }
    
    /**
     * @brief Reconfigure for different architecture
     * @param config New configuration
     * @return true if successful
     */
    bool Reconfigure(const AsmConfig& config);
    
    /**
     * @brief Get architecture name
     * @return Architecture name string
     */
    std::string GetArchitectureName() const;
    
    /**
     * @brief Add symbol to symbol table
     * @param name Symbol name
     * @param address Symbol address
     */
    void AddSymbol(const std::string& name, uint64_t address);
    
    /**
     * @brief Clear symbol table
     */
    void ClearSymbols();
    
    /**
     * @brief Get symbol table
     * @return Reference to symbol table
     */
    const std::map<std::string, uint64_t>& GetSymbols() const { return m_symbols; }

private:
#ifdef HAS_KEYSTONE
    ks_engine* m_handle;        ///< Keystone handle
#else
    void* m_handle;             ///< Opaque handle (not used without Keystone)
#endif
    AsmConfig m_config;         ///< Current configuration
    int m_lastError;            ///< Last error code
    std::map<std::string, uint64_t> m_symbols; ///< Symbol table

    /**
     * @brief Initialize Keystone engine
     * @return true if successful
     */
    bool Initialize();

    /**
     * @brief Close Keystone engine
     */
    void Cleanup();

    /**
     * @brief Set Keystone options based on config
     */
    void ConfigureOptions();

    /**
     * @brief Process assembly result
     */
    AsmResult ProcessResult(unsigned char* encode, size_t size, size_t stmtCount);
};

/**
 * @brief Quick assemble function (stateless)
 * @param arch Architecture to assemble
 * @param instruction Assembly instruction string
 * @param baseAddress Base address
 * @return Assembly result
 */
AsmResult QuickAssemble(
    Architecture arch,
    const std::string& instruction,
    uint64_t baseAddress = 0x1000
);

/**
 * @brief Format machine code as hex string
 * @param code Machine code bytes
 * @return Hex string (e.g., "48 89 C3")
 */
std::string FormatMachineCode(const std::vector<uint8_t>& code);

/**
 * @brief Format machine code with address
 * @param code Machine code bytes
 * @param address Base address
 * @return Formatted string
 */
std::string FormatMachineCodeWithAddress(
    const std::vector<uint8_t>& code, 
    uint64_t address
);

} // namespace RE
} // namespace RawrXD
