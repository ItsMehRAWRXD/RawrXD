// ============================================================================
// MASM64 Kernel Loader Implementation
// ============================================================================
// Loads COFF object files and maps executable code into memory
// ============================================================================

#include "MASM64KernelLoader.hpp"
#include <iostream>
#include <fstream>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

namespace RawrXD {
namespace Execution {

// ============================================================================
// Construction / Destruction
// ============================================================================

MASM64KernelLoader::MASM64KernelLoader() = default;

MASM64KernelLoader::~MASM64KernelLoader() {
    if (loaded_) {
        Unload();
    }
}

// ============================================================================
// Load Object File
// ============================================================================

bool MASM64KernelLoader::LoadObjectFile(const std::string& filepath) {
    if (loaded_) {
        std::cerr << "[MASM64Loader] Already loaded, unload first\n";
        return false;
    }

    filepath_ = filepath;
    std::cout << "[MASM64Loader] Loading: " << filepath << "\n";

    // Read file
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[MASM64Loader] Failed to open file: " << filepath << "\n";
        return false;
    }

    auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    file_data_.resize(size);
    if (!file.read(reinterpret_cast<char*>(file_data_.data()), size)) {
        std::cerr << "[MASM64Loader] Failed to read file\n";
        return false;
    }
    file.close();

    std::cout << "[MASM64Loader] Read " << file_data_.size() << " bytes\n";

    // Parse COFF
    if (!ParseCOFF()) {
        Cleanup();
        return false;
    }

    // Map sections to executable memory
    if (!MapSections()) {
        Cleanup();
        return false;
    }

    // Resolve symbols
    if (!ResolveSymbols()) {
        Cleanup();
        return false;
    }

    loaded_ = true;
    std::cout << "[MASM64Loader] Loaded " << symbols_.size() << " kernels\n";
    
    return true;
}

void MASM64KernelLoader::Unload() {
    if (!loaded_) return;

    std::cout << "[MASM64Loader] Unloading...\n";

    Cleanup();
    loaded_ = false;
}

// ============================================================================
// Parse COFF Format
// ============================================================================

bool MASM64KernelLoader::ParseCOFF() {
    if (file_data_.size() < sizeof(COFFHeader)) {
        std::cerr << "[MASM64Loader] File too small for COFF header\n";
        return false;
    }

    // Parse header
    header_ = reinterpret_cast<COFFHeader*>(file_data_.data());

    // Verify machine type
    if (header_->machine != IMAGE_FILE_MACHINE_AMD64) {
        std::cerr << "[MASM64Loader] Not an x64 object file (machine=0x" 
                  << std::hex << header_->machine << std::dec << ")\n";
        return false;
    }

    std::cout << "[MASM64Loader] COFF Header:\n";
    std::cout << "  Machine: x64 (0x" << std::hex << header_->machine << std::dec << ")\n";
    std::cout << "  Sections: " << header_->num_sections << "\n";
    std::cout << "  Symbols: " << header_->num_symbols << "\n";

    // Parse section headers
    size_t section_offset = sizeof(COFFHeader) + header_->optional_header_size;
    
    for (uint16_t i = 0; i < header_->num_sections; ++i) {
        if (section_offset + sizeof(COFFSectionHeader) > file_data_.size()) {
            std::cerr << "[MASM64Loader] Section header " << i << " out of bounds\n";
            return false;
        }

        auto* section = reinterpret_cast<COFFSectionHeader*>(
            file_data_.data() + section_offset);
        section_headers_.push_back(section);

        std::string section_name(section->name, 8);
        // Trim nulls
        section_name.erase(std::find(section_name.begin(), section_name.end(), '\0'), 
                          section_name.end());

        std::cout << "  Section " << i << ": " << section_name 
                  << " (size=" << section->raw_data_size 
                  << ", addr=0x" << std::hex << section->virtual_address << std::dec << ")\n";

        section_offset += sizeof(COFFSectionHeader);
    }

    // Parse symbol table
    if (header_->symbol_table_offset > 0) {
        symbol_table_ = reinterpret_cast<COFFSymbol*>(
            file_data_.data() + header_->symbol_table_offset);
        
        // String table follows symbol table
        size_t symbol_table_size = header_->num_symbols * sizeof(COFFSymbol);
        string_table_ = reinterpret_cast<char*>(
            file_data_.data() + header_->symbol_table_offset + symbol_table_size);
        
        // First 4 bytes of string table is its size
        if (header_->symbol_table_offset + symbol_table_size + 4 <= file_data_.size()) {
            string_table_size_ = *reinterpret_cast<uint32_t*>(string_table_);
            string_table_ += 4;  // Skip size field
        }

        std::cout << "[MASM64Loader] String table size: " << string_table_size_ << " bytes\n";
    }

    return true;
}

// ============================================================================
// Map Sections to Executable Memory
// ============================================================================

bool MASM64KernelLoader::MapSections() {
    for (size_t i = 0; i < section_headers_.size(); ++i) {
        auto* header = section_headers_[i];
        
        LoadedSection section;
        section.name = std::string(header->name, 8);
        section.name.erase(std::find(section.name.begin(), section.name.end(), '\0'),
                          section.name.end());
        section.size = header->raw_data_size;
        section.characteristics = header->characteristics;
        section.executable = IsExecutableSection(header);

        if (section.size == 0) {
            sections_.push_back(section);
            continue;
        }

        // Allocate memory for section
        section.memory = AllocateExecutableMemory(section.size);
        if (!section.memory) {
            std::cerr << "[MASM64Loader] Failed to allocate memory for section " 
                      << section.name << "\n";
            return false;
        }

        // Copy data
        if (header->raw_data_offset > 0 && header->raw_data_size > 0) {
            if (header->raw_data_offset + header->raw_data_size <= file_data_.size()) {
                std::memcpy(section.memory, 
                           file_data_.data() + header->raw_data_offset,
                           header->raw_data_size);
            }
        }

        sections_.push_back(section);

        std::cout << "[MASM64Loader] Mapped section '" << section.name 
                  << "' at " << section.memory 
                  << " (executable=" << section.executable << ")\n";
    }

    return true;
}

// ============================================================================
// Resolve Symbols
// ============================================================================

bool MASM64KernelLoader::ResolveSymbols() {
    if (!symbol_table_ || header_->num_symbols == 0) {
        std::cout << "[MASM64Loader] No symbols to resolve\n";
        return true;
    }

    std::cout << "[MASM64Loader] Resolving " << header_->num_symbols << " symbols...\n";

    for (uint32_t i = 0; i < header_->num_symbols; ) {
        COFFSymbol* symbol = &symbol_table_[i];
        
        std::string name = GetSymbolName(symbol);
        
        // Skip debug symbols and aux entries
        if (symbol->storage_class == 2 &&  // EXTERNAL
            symbol->section_number > 0 &&   // Defined in a section
            symbol->section_number <= static_cast<int16_t>(sections_.size())) {
            
            uint16_t section_idx = symbol->section_number - 1;
            if (section_idx < sections_.size()) {
                auto& section = sections_[section_idx];
                
                KernelSymbol kernel;
                kernel.name = name;
                kernel.section_number = section_idx;
                kernel.section_offset = symbol->value;
                
                // Calculate actual address
                if (section.memory && symbol->value < section.size) {
                    kernel.address = static_cast<char*>(section.memory) + symbol->value;
                }

                // Only add if it looks like a kernel function
                if (name.find("Sovereign_") == 0 || 
                    name.find("Kernel_") == 0 ||
                    section.executable) {
                    symbols_[name] = kernel;
                    std::cout << "  Kernel: " << name << " at " << kernel.address << "\n";
                }
            }
        }

        // Skip aux symbols
        i += 1 + symbol->num_aux_symbols;
    }

    return true;
}

// ============================================================================
// Get Symbol Name
// ============================================================================

std::string MASM64KernelLoader::GetSymbolName(const COFFSymbol* symbol) const {
    // Check if using string table
    if (symbol->name.short_name[0] == 0 && symbol->name.short_name[1] == 0 &&
        symbol->name.short_name[2] == 0 && symbol->name.short_name[3] == 0) {
        // Long name in string table
        uint32_t offset = symbol->name.long_name.string_table_offset;
        if (offset < string_table_size_) {
            return std::string(string_table_ + offset);
        }
        return "";
    }
    
    // Short name (8 bytes, null-terminated)
    std::string name(symbol->name.short_name, 8);
    name.erase(std::find(name.begin(), name.end(), '\0'), name.end());
    return name;
}

// ============================================================================
// Check if Section is Executable
// ============================================================================

bool MASM64KernelLoader::IsExecutableSection(const COFFSectionHeader* section) const {
    return (section->characteristics & IMAGE_SCN_CNT_CODE) != 0 ||
           (section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}

// ============================================================================
// Get Kernel Function
// ============================================================================

KernelFunction MASM64KernelLoader::GetKernelFunction(const std::string& name) const {
    auto it = symbols_.find(name);
    if (it != symbols_.end() && it->second.address) {
        return reinterpret_cast<KernelFunction>(it->second.address);
    }
    return nullptr;
}

void* MASM64KernelLoader::GetKernelAddress(const std::string& name) const {
    auto it = symbols_.find(name);
    if (it != symbols_.end()) {
        return it->second.address;
    }
    return nullptr;
}

bool MASM64KernelLoader::HasKernel(const std::string& name) const {
    return symbols_.find(name) != symbols_.end();
}

// ============================================================================
// Get Kernel Names
// ============================================================================

std::vector<std::string> MASM64KernelLoader::GetKernelNames() const {
    std::vector<std::string> names;
    for (const auto& [name, symbol] : symbols_) {
        names.push_back(name);
    }
    return names;
}

const KernelSymbol* MASM64KernelLoader::GetKernelInfo(const std::string& name) const {
    auto it = symbols_.find(name);
    if (it != symbols_.end()) {
        return &it->second;
    }
    return nullptr;
}

// ============================================================================
// Platform-Specific Memory Allocation
// ============================================================================

void* MASM64KernelLoader::AllocateExecutableMemory(size_t size) {
#ifdef _WIN32
    // Round up to page size
    size_t page_size = 4096;
    size_t alloc_size = (size + page_size - 1) & ~(page_size - 1);
    
    void* ptr = VirtualAlloc(nullptr, alloc_size, 
                              MEM_COMMIT | MEM_RESERVE, 
                              PAGE_EXECUTE_READWRITE);
    if (ptr) {
        allocated_blocks_.push_back(ptr);
    }
    return ptr;
#else
    // POSIX implementation would use mmap with PROT_EXEC
    return nullptr;
#endif
}

void MASM64KernelLoader::FreeExecutableMemory(void* ptr, size_t size) {
#ifdef _WIN32
    if (ptr) {
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
#else
    (void)ptr;
    (void)size;
#endif
}

// ============================================================================
// Cleanup
// ============================================================================

void MASM64KernelLoader::Cleanup() {
    // Free allocated memory
    for (auto& section : sections_) {
        if (section.memory) {
            FreeExecutableMemory(section.memory, section.size);
            section.memory = nullptr;
        }
    }
    sections_.clear();
    symbols_.clear();
    section_headers_.clear();
    
    // Clear COFF data
    file_data_.clear();
    header_ = nullptr;
    symbol_table_ = nullptr;
    string_table_ = nullptr;
    string_table_size_ = 0;

#ifdef _WIN32
    allocated_blocks_.clear();
#endif
}

// ============================================================================
// Debug Output
// ============================================================================

void MASM64KernelLoader::DumpInfo() const {
    std::cout << "\n[MASM64Loader] Object File Info:\n";
    std::cout << "  File: " << filepath_ << "\n";
    std::cout << "  Loaded: " << (loaded_ ? "Yes" : "No") << "\n";
    std::cout << "  Sections: " << sections_.size() << "\n";
    std::cout << "  Kernels: " << symbols_.size() << "\n";
    
    if (!symbols_.empty()) {
        std::cout << "\n  Kernel Functions:\n";
        for (const auto& [name, symbol] : symbols_) {
            std::cout << "    " << name << " @ " << symbol.address 
                      << " (section " << symbol.section_number 
                      << "+" << symbol.section_offset << ")\n";
        }
    }
}

// ============================================================================
// Factory Function
// ============================================================================

std::unique_ptr<MASM64KernelLoader> CreateKernelLoader() {
    return std::make_unique<MASM64KernelLoader>();
}

// ============================================================================
// Kernel Dispatch with Timing
// ============================================================================

bool InvokeKernelTimed(KernelFunction func, void* input, void* output, 
                       size_t count, uint64_t* out_cycles) {
    if (!func) return false;

#ifdef _WIN32
    // Read timestamp counter
    uint64_t start = __rdtsc();
    
    // Call kernel
    func(input, output, count);
    
    // Read end timestamp
    uint64_t end = __rdtsc();
    
    if (out_cycles) {
        *out_cycles = end - start;
    }
#else
    // Fallback without timing
    func(input, output, count);
    if (out_cycles) {
        *out_cycles = 0;
    }
#endif

    return true;
}

} // namespace Execution
} // namespace RawrXD
