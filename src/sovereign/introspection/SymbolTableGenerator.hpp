#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <unordered_map>
#include <map>
#include <mutex>
#include <functional>

// =============================================================================
// Symbol Table Generator - Runtime Binary Introspection
// Allows the Agent to see its own code as addressable symbols
// =============================================================================

namespace RawrXD {
namespace Sovereign {

// =============================================================================
// Symbol Types
// =============================================================================

enum class SymbolType : uint8_t {
    FUNCTION = 0,       // Executable code
    DATA = 1,           // Mutable data
    CONSTANT = 2,       // Read-only data
    BSS = 3,            // Uninitialized data
    THREAD_LOCAL = 4, // Thread-local storage
    UNKNOWN = 255
};

// =============================================================================
// Symbol Entry - Represents a named memory region
// =============================================================================

struct SymbolEntry {
    std::string name;           // Symbol name (e.g., "Deep2Engine::Linear")
    uintptr_t address;          // Absolute memory address
    size_t size;                // Size in bytes
    SymbolType type;            // Symbol classification
    uint32_t flags;             // Protection flags (R/W/X)
    
    // For functions: entry point, for data: data pointer
    union {
        void* entry_point;
        void* data_ptr;
    };
    
    SymbolEntry() 
        : address(0)
        , size(0)
        , type(SymbolType::UNKNOWN)
        , flags(0)
        , entry_point(nullptr)
    {}
};

// =============================================================================
// Memory Region - Contiguous executable region
// =============================================================================

struct MemoryRegion {
    uintptr_t base;             // Base address
    size_t size;                // Region size
    uint32_t protection;        // Windows protection flags
    std::string module_name;    // DLL/EXE name
    
    bool IsExecutable() const { return protection & 0x10; }  // PAGE_EXECUTE*
    bool IsWritable() const { return protection & 0x02; }    // PAGE_WRITE*
    bool IsReadable() const { return protection & 0x01; }   // PAGE_READ*
};

// =============================================================================
// Symbol Table Generator
// =============================================================================

class SymbolTableGenerator {
public:
    using SymbolCallback = std::function<void(const SymbolEntry&)>;
    using RegionCallback = std::function<void(const MemoryRegion&)>;
    
    static SymbolTableGenerator& Instance();
    
    // Initialize symbol table from current process
    bool Initialize();
    
    // Scan all memory regions for executable code
    bool ScanProcessMemory();
    
    // Parse PE headers to find exported symbols
    bool ParseModuleExports(const std::string& module_name);
    
    // Parse debug symbols (PDB) if available
    bool ParseDebugSymbols(const std::string& pdb_path);
    
    // Build symbol table from runtime analysis
    bool BuildFromRuntimeAnalysis();
    
    // -------------------------------------------------------------------------
    // Symbol Lookup (Hot Path)
    // -------------------------------------------------------------------------
    
    // Find symbol by exact name
    const SymbolEntry* FindSymbol(const std::string& name) const;
    
    // Get symbol by name (alias for FindSymbol)
    const SymbolEntry* GetSymbol(const std::string& name) const;
    
    // Get symbol address by name
    uintptr_t GetAddress(const std::string& name) const;
    
    // Find symbol by address (nearest match)
    const SymbolEntry* FindSymbolByAddress(uintptr_t addr) const;
    
    // Find all symbols matching pattern (e.g., "Deep2Engine::*")
    std::vector<const SymbolEntry*> FindSymbolsByPattern(const std::string& pattern) const;
    
    // Find symbols by pattern (returns vector of pointers)
    std::vector<const SymbolEntry*> FindSymbols(const std::string& pattern) const;
    
    // Get symbol at specific address range
    std::vector<const SymbolEntry*> GetSymbolsInRange(uintptr_t start, uintptr_t end) const;
    
    // -------------------------------------------------------------------------
    // Memory Region Queries
    // -------------------------------------------------------------------------
    
    // Get region containing address
    const MemoryRegion* GetRegionForAddress(uintptr_t addr) const;
    
    // Get all executable regions
    std::vector<MemoryRegion> GetExecutableRegions() const;
    
    // Check if address is valid code
    bool IsValidCodeAddress(uintptr_t addr) const;
    
    // Check if address is writable data
    bool IsWritableDataAddress(uintptr_t addr) const;
    
    // Check if address is readable
    bool IsAddressReadable(uintptr_t addr) const;
    
    // Check if address is writable
    bool IsAddressWritable(uintptr_t addr) const;
    
    // Check if patch target is valid (by name)
    bool IsValidPatchTarget(const std::string& name) const;
    
    // Check if patch target is valid (by address)
    bool IsValidPatchTarget(uintptr_t addr) const;
    
    // -------------------------------------------------------------------------
    // Symbol Table Management
    // -------------------------------------------------------------------------
    
    // Add custom symbol (for JIT code)
    bool RegisterSymbol(const SymbolEntry& entry);
    
    // Remove symbol
    bool UnregisterSymbol(const std::string& name);
    
    // Update symbol address (after hotpatch)
    bool UpdateSymbolAddress(const std::string& name, uintptr_t new_addr);
    
    // Export symbol table to file
    bool ExportToFile(const std::string& path) const;
    
    // Export symbol table to binary
    std::vector<uint8_t> ExportToBinary() const;
    
    // Import symbol table from file
    bool ImportFromFile(const std::string& path);
    
    // -------------------------------------------------------------------------
    // Statistics
    // -------------------------------------------------------------------------
    size_t GetSymbolCount() const { return symbols_.size(); }
    size_t GetRegionCount() const { return regions_.size(); }
    
    // Iterate all symbols
    void ForEachSymbol(SymbolCallback callback) const;
    
    // Iterate all regions
    void ForEachRegion(RegionCallback callback) const;
    
private:
    SymbolTableGenerator() = default;
    ~SymbolTableGenerator() = default;
    
    SymbolTableGenerator(const SymbolTableGenerator&) = delete;
    SymbolTableGenerator& operator=(const SymbolTableGenerator&) = delete;
    
    // Internal data structures
    mutable std::mutex mutex_;
    std::unordered_map<std::string, SymbolEntry> symbols_;
    std::vector<MemoryRegion> regions_;
    
    // Address-to-symbol index for fast lookup
    std::map<uintptr_t, std::string> addr_index_;
    
    // Platform-specific implementation
    bool ScanWindowsModules();
    bool ParsePEExports(HMODULE hModule, const std::string& module_name);
    
    // Helper functions
    uint32_t GetPageProtection(void* addr);
    std::string DemangleName(const std::string& mangled);
};

// =============================================================================
// Scoped Symbol Lookup - RAII for temporary symbol access
// =============================================================================

class ScopedSymbolAccess {
public:
    explicit ScopedSymbolAccess(const std::string& symbol_name);
    ~ScopedSymbolAccess();
    
    bool IsValid() const { return symbol_ != nullptr; }
    const SymbolEntry* GetSymbol() const { return symbol_; }
    
    // Access symbol memory (read-only by default)
    template<typename T>
    const T* As() const {
        return symbol_ ? reinterpret_cast<const T*>(symbol_->address) : nullptr;
    }
    
private:
    const SymbolEntry* symbol_;
};

// =============================================================================
// Convenience Macros
// =============================================================================

#define SYMBOL_LOOKUP(name) \
    RawrXD::Sovereign::SymbolTableGenerator::Instance().FindSymbol(name)

#define SYMBOL_ADDRESS(name) \
    (RawrXD::Sovereign::SymbolTableGenerator::Instance().FindSymbol(name) \
        ? RawrXD::Sovereign::SymbolTableGenerator::Instance().FindSymbol(name)->address \
        : 0)

#define REGISTER_JIT_SYMBOL(name, addr, size) \
    RawrXD::Sovereign::SymbolTableGenerator::Instance().RegisterSymbol( \
        RawrXD::Sovereign::SymbolEntry{name, addr, size, \
            RawrXD::Sovereign::SymbolType::FUNCTION, 0x10, {reinterpret_cast<void*>(addr)}})

} // namespace Sovereign
} // namespace RawrXD
