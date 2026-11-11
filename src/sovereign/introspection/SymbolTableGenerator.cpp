#include "SymbolTableGenerator.hpp"
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <iostream>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

namespace RawrXD {
namespace Sovereign {

// =============================================================================
// Singleton
// =============================================================================

SymbolTableGenerator& SymbolTableGenerator::Instance() {
    static SymbolTableGenerator instance;
    return instance;
}

// =============================================================================
// Initialization
// =============================================================================

bool SymbolTableGenerator::Initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Initialize DbgHelp
    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS);
    if (!SymInitialize(GetCurrentProcess(), nullptr, TRUE)) {
        // Continue without symbols
    }
    
    // Scan process memory
    return ScanProcessMemory();
}

// =============================================================================
// Memory Scanning
// =============================================================================

bool SymbolTableGenerator::ScanProcessMemory() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    regions_.clear();
    
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0;
    
    while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT) {
            MemoryRegion region;
            region.base = (uintptr_t)mbi.BaseAddress;
            region.size = mbi.RegionSize;
            region.protection = mbi.Protect;
            
            // Get module name
            HMODULE hMod;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, 
                                   (LPCSTR)mbi.BaseAddress, &hMod)) {
                char modName[MAX_PATH];
                if (GetModuleFileNameA(hMod, modName, MAX_PATH)) {
                    region.module_name = modName;
                }
                FreeLibrary(hMod);
            }
            
            regions_.push_back(region);
        }
        
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    
    return ScanWindowsModules();
}

bool SymbolTableGenerator::ScanWindowsModules() {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    if (!EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        return false;
    }
    
    DWORD numMods = cbNeeded / sizeof(HMODULE);
    
    for (DWORD i = 0; i < numMods; i++) {
        char modName[MAX_PATH];
        if (GetModuleFileNameExA(GetCurrentProcess(), hMods[i], modName, MAX_PATH)) {
            ParsePEExports(hMods[i], modName);
        }
    }
    
    return true;
}

bool SymbolTableGenerator::ParsePEExports(HMODULE hModule, const std::string& module_name) {
    if (!hModule) return false;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
    
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRVA) return false;
    
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);
    
    DWORD* nameRVAs = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    DWORD* funcRVAs = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* funcName = (const char*)((BYTE*)hModule + nameRVAs[i]);
        WORD ordinal = ordinals[i];
        uintptr_t funcAddr = (uintptr_t)hModule + funcRVAs[ordinal];
        
        SymbolEntry entry;
        entry.name = funcName;
        entry.address = funcAddr;
        entry.size = 0; // Unknown without disassembly
        entry.type = SymbolType::FUNCTION;
        entry.flags = 0x10; // PAGE_EXECUTE
        entry.entry_point = (void*)funcAddr;
        
        symbols_[entry.name] = entry;
        addr_index_[funcAddr] = entry.name;
    }
    
    return true;
}

// =============================================================================
// Symbol Lookup
// =============================================================================

const SymbolEntry* SymbolTableGenerator::FindSymbol(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = symbols_.find(name);
    return (it != symbols_.end()) ? &it->second : nullptr;
}

const SymbolEntry* SymbolTableGenerator::GetSymbol(const std::string& name) const {
    return FindSymbol(name);
}

std::vector<const SymbolEntry*> SymbolTableGenerator::FindSymbols(const std::string& pattern) const {
    return FindSymbolsByPattern(pattern);
}

const SymbolEntry* SymbolTableGenerator::FindSymbolByAddress(uintptr_t addr) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Find nearest symbol
    auto it = addr_index_.upper_bound(addr);
    if (it == addr_index_.begin()) return nullptr;
    
    --it;
    auto sym_it = symbols_.find(it->second);
    if (sym_it == symbols_.end()) return nullptr;
    
    // Check if address is within symbol bounds
    const auto& sym = sym_it->second;
    if (addr >= sym.address && addr < sym.address + sym.size) {
        return &sym;
    }
    
    return nullptr;
}

std::vector<const SymbolEntry*> SymbolTableGenerator::FindSymbolsByPattern(const std::string& pattern) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<const SymbolEntry*> results;
    
    for (const auto& pair : symbols_) {
        if (pair.first.find(pattern) != std::string::npos) {
            results.push_back(&pair.second);
        }
    }
    
    return results;
}

// =============================================================================
// Memory Region Queries
// =============================================================================

const MemoryRegion* SymbolTableGenerator::GetRegionForAddress(uintptr_t addr) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& region : regions_) {
        if (addr >= region.base && addr < region.base + region.size) {
            return &region;
        }
    }
    
    return nullptr;
}

bool SymbolTableGenerator::IsValidCodeAddress(uintptr_t addr) const {
    auto region = GetRegionForAddress(addr);
    return region && region->IsExecutable();
}

bool SymbolTableGenerator::IsWritableDataAddress(uintptr_t addr) const {
    auto region = GetRegionForAddress(addr);
    return region && region->IsWritable() && !region->IsExecutable();
}

// =============================================================================
// Symbol Registration
// =============================================================================

bool SymbolTableGenerator::RegisterSymbol(const SymbolEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    symbols_[entry.name] = entry;
    addr_index_[entry.address] = entry.name;
    
    return true;
}

bool SymbolTableGenerator::UpdateSymbolAddress(const std::string& name, uintptr_t new_addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = symbols_.find(name);
    if (it == symbols_.end()) return false;
    
    // Remove old address index
    addr_index_.erase(it->second.address);
    
    // Update address
    it->second.address = new_addr;
    it->second.entry_point = (void*)new_addr;
    
    // Add new address index
    addr_index_[new_addr] = name;
    
    return true;
}

// =============================================================================
// Iteration
// =============================================================================

void SymbolTableGenerator::ForEachSymbol(SymbolCallback callback) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& pair : symbols_) {
        callback(pair.second);
    }
}

void SymbolTableGenerator::ForEachRegion(RegionCallback callback) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& region : regions_) {
        callback(region);
    }
}

// =============================================================================
// Additional Methods for PuppeteerAPI
// =============================================================================

uintptr_t SymbolTableGenerator::GetAddress(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = symbols_.find(name);
    return (it != symbols_.end()) ? it->second.address : 0;
}

bool SymbolTableGenerator::IsAddressReadable(uintptr_t addr) const {
    auto region = GetRegionForAddress(addr);
    return region && region->IsReadable();
}

bool SymbolTableGenerator::IsAddressWritable(uintptr_t addr) const {
    auto region = GetRegionForAddress(addr);
    return region && region->IsWritable();
}

bool SymbolTableGenerator::IsValidPatchTarget(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = symbols_.find(name);
    if (it == symbols_.end()) return false;
    
    // Check if it's in an executable region
    auto region = GetRegionForAddress(it->second.address);
    return region && region->IsExecutable();
}

bool SymbolTableGenerator::IsValidPatchTarget(uintptr_t addr) const {
    auto region = GetRegionForAddress(addr);
    return region && region->IsExecutable();
}

std::vector<uint8_t> SymbolTableGenerator::ExportToBinary() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<uint8_t> result;
    
    // Simple binary format: count (4 bytes) + entries
    uint32_t count = static_cast<uint32_t>(symbols_.size());
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&count), 
                  reinterpret_cast<uint8_t*>(&count) + sizeof(count));
    
    for (const auto& pair : symbols_) {
        const auto& sym = pair.second;
        // Write: address (8), size (4), name_len (4), name (N)
        result.insert(result.end(), reinterpret_cast<const uint8_t*>(&sym.address),
                      reinterpret_cast<const uint8_t*>(&sym.address) + sizeof(sym.address));
        result.insert(result.end(), reinterpret_cast<const uint8_t*>(&sym.size),
                      reinterpret_cast<const uint8_t*>(&sym.size) + sizeof(sym.size));
        uint32_t name_len = static_cast<uint32_t>(sym.name.size());
        result.insert(result.end(), reinterpret_cast<uint8_t*>(&name_len),
                      reinterpret_cast<uint8_t*>(&name_len) + sizeof(name_len));
        result.insert(result.end(), sym.name.begin(), sym.name.end());
    }
    
    return result;
}

} // namespace Sovereign
} // namespace RawrXD
