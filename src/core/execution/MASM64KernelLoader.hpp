// ============================================================================
// MASM64 Kernel Loader
// ============================================================================
// Loads MASM64 object files (.obj) and provides callable function pointers
// Parses COFF format and maps executable sections into memory
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <cstdint>

namespace RawrXD {
namespace Execution {

// ============================================================================
// COFF File Structures (x64)
// ============================================================================

#pragma pack(push, 1)

struct COFFHeader {
    uint16_t machine;           // 0x8664 for x64
    uint16_t num_sections;
    uint32_t timestamp;
    uint32_t symbol_table_offset;
    uint32_t num_symbols;
    uint16_t optional_header_size;
    uint16_t characteristics;
};

struct COFFSectionHeader {
    char name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_data_size;
    uint32_t raw_data_offset;
    uint32_t relocations_offset;
    uint32_t line_numbers_offset;
    uint16_t num_relocations;
    uint16_t num_line_numbers;
    uint32_t characteristics;
};

struct COFFSymbol {
    union {
        char short_name[8];
        struct {
            uint32_t zero;
            uint32_t string_table_offset;
        } long_name;
    } name;
    uint32_t value;
    uint16_t section_number;
    uint16_t type;
    uint8_t storage_class;
    uint8_t num_aux_symbols;
};

#pragma pack(pop)

// Section characteristics
constexpr uint32_t IMAGE_SCN_CNT_CODE = 0x00000020;
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
constexpr uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;

// Machine types
constexpr uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;

// ============================================================================
// Loaded Kernel Function
// ============================================================================

using KernelFunction = void (*)(void* input, void* output, size_t count);

// ============================================================================
// Loaded Section
// ============================================================================

struct LoadedSection {
    std::string name;
    void* memory = nullptr;
    size_t size = 0;
    uint32_t characteristics = 0;
    bool executable = false;
};

// ============================================================================
// Kernel Symbol
// ============================================================================

struct KernelSymbol {
    std::string name;
    void* address = nullptr;
    uint32_t section_number = 0;
    uint32_t section_offset = 0;
    uint64_t invocation_count = 0;
    uint64_t total_cycles = 0;
};

// ============================================================================
// MASM64 Kernel Loader
// ============================================================================

class MASM64KernelLoader {
public:
    MASM64KernelLoader();
    ~MASM64KernelLoader();

    // Load object file
    bool LoadObjectFile(const std::string& filepath);
    void Unload();
    bool IsLoaded() const { return loaded_; }

    // Get loaded kernel function
    KernelFunction GetKernelFunction(const std::string& name) const;
    void* GetKernelAddress(const std::string& name) const;
    bool HasKernel(const std::string& name) const;

    // Get all kernel names
    std::vector<std::string> GetKernelNames() const;

    // Get kernel info
    const KernelSymbol* GetKernelInfo(const std::string& name) const;

    // Statistics
    size_t GetNumSections() const { return sections_.size(); }
    size_t GetNumKernels() const { return symbols_.size(); }

    // Debug
    void DumpInfo() const;

private:
    bool loaded_ = false;
    std::string filepath_;
    
    // COFF data
    std::vector<uint8_t> file_data_;
    COFFHeader* header_ = nullptr;
    std::vector<COFFSectionHeader*> section_headers_;
    COFFSymbol* symbol_table_ = nullptr;
    char* string_table_ = nullptr;
    size_t string_table_size_ = 0;

    // Loaded data
    std::vector<LoadedSection> sections_;
    std::unordered_map<std::string, KernelSymbol> symbols_;

    // Platform-specific memory
#ifdef _WIN32
    std::vector<void*> allocated_blocks_;
#endif

    // Internal helpers
    bool ParseCOFF();
    bool MapSections();
    bool ResolveSymbols();
    void Cleanup();

    std::string GetSymbolName(const COFFSymbol* symbol) const;
    bool IsExecutableSection(const COFFSectionHeader* section) const;

    // Memory allocation (platform-specific)
    void* AllocateExecutableMemory(size_t size);
    void FreeExecutableMemory(void* ptr, size_t size);
};

// ============================================================================
// Factory Function
// ============================================================================

std::unique_ptr<MASM64KernelLoader> CreateKernelLoader();

// ============================================================================
// Kernel Dispatch Helper
// ============================================================================

struct KernelDispatchContext {
    void* input;
    void* output;
    size_t count;
    uint64_t start_cycles;
    uint64_t end_cycles;
};

// Invoke kernel with timing
bool InvokeKernelTimed(KernelFunction func, void* input, void* output, 
                       size_t count, uint64_t* out_cycles);

} // namespace Execution
} // namespace RawrXD
