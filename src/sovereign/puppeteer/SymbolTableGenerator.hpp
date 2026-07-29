#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>

namespace RawrXD {
namespace Sovereign {

// Symbol entry for runtime introspection
struct SymbolEntry {
    std::string name;
    uintptr_t address;
    size_t size;
    uint32_t flags;        // 0x1=Code, 0x2=Data, 0x4=Export
    uint32_t hash;         // CRC32 of name for fast lookup
};

// Memory region descriptor
struct MemoryRegion {
    uintptr_t base;
    size_t size;
    uint32_t protection;
    std::string moduleName;
};

// The Symbol Table - Agent's "Self-Awareness"
class SymbolTableGenerator {
public:
    static SymbolTableGenerator& Instance();
    
    // Initialize by scanning current process modules
    bool Initialize();
    
    // Scan specific module (DLL/EXE) for exports and code
    bool ScanModule(const std::string& moduleName);
    
    // Runtime symbol resolution
    uintptr_t GetAddress(const std::string& symbolName) const;
    const SymbolEntry* GetSymbol(const std::string& symbolName) const;
    
    // Get all symbols matching pattern (for fuzzy matching)
    std::vector<const SymbolEntry*> FindSymbols(const std::string& pattern) const;
    
    // Memory region queries
    bool IsAddressExecutable(uintptr_t addr) const;
    bool IsAddressReadable(uintptr_t addr) const;
    bool IsAddressWritable(uintptr_t addr) const;
    const MemoryRegion* GetRegionContaining(uintptr_t addr) const;
    
    // Hotpatch target validation
    bool IsValidPatchTarget(const std::string& functionName) const;
    bool IsValidPatchTarget(uintptr_t address) const;
    
    // Export symbol table for agent consumption
    std::vector<uint8_t> ExportToBinary() const;
    bool ImportFromBinary(const uint8_t* data, size_t size);
    
    // Refresh dynamic symbols (for JIT compiled code)
    void RefreshDynamicSymbols();
    
private:
    SymbolTableGenerator() = default;
    ~SymbolTableGenerator() = default;
    
    SymbolTableGenerator(const SymbolTableGenerator&) = delete;
    SymbolTableGenerator& operator=(const SymbolTableGenerator&) = delete;
    
    bool ParsePEExports(HMODULE hModule, const std::string& moduleName);
    uint32_t CalculateCRC32(const std::string& str) const;
    
    std::unordered_map<std::string, SymbolEntry> symbols_;
    std::unordered_map<uint32_t, std::vector<const SymbolEntry*>> hashIndex_;
    std::vector<MemoryRegion> regions_;
    bool initialized_ = false;
};

// Macro for auto-registration of agent-visible functions
#define AGENT_EXPORT __declspec(dllexport)
#define AGENT_SYMBOL(name) \
    extern "C" AGENT_EXPORT void __agent_sym_##name() {} \
    static struct __AgentSymReg_##name { \
        __AgentSymReg_##name() { \
            RawrXD::Sovereign::SymbolTableGenerator::Instance().RefreshDynamicSymbols(); \
        } \
    } __agent_sym_reg_##name;

} // namespace Sovereign
} // namespace RawrXD
