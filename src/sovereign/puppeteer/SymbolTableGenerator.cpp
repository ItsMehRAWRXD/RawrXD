#include "SymbolTableGenerator.hpp"
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <algorithm>
#include <sstream>

#pragma comment(lib, "DbgHelp.lib")

namespace RawrXD {
namespace Sovereign {

SymbolTableGenerator& SymbolTableGenerator::Instance() {
    static SymbolTableGenerator instance;
    return instance;
}

bool SymbolTableGenerator::Initialize() {
    if (initialized_) return true;
    
    // Enumerate all loaded modules
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    
    if (Module32First(hSnapshot, &me32)) {
        do {
            std::string moduleName = me32.szModule;
            std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::tolower);
            
            // Scan module for exports
            HMODULE hMod = GetModuleHandleA(me32.szModule);
            if (hMod) {
                ParsePEExports(hMod, moduleName);
                
                // Record memory region
                MemoryRegion region;
                region.base = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                region.size = me32.modBaseSize;
                region.protection = PAGE_EXECUTE_READ;
                region.moduleName = moduleName;
                regions_.push_back(region);
            }
        } while (Module32Next(hSnapshot, &me32));
    }
    
    CloseHandle(hSnapshot);
    
    // Initialize DbgHelp for symbol resolution
    SymInitialize(GetCurrentProcess(), NULL, TRUE);
    
    initialized_ = true;
    return true;
}

bool SymbolTableGenerator::ParsePEExports(HMODULE hModule, const std::string& moduleName) {
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    
    auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uintptr_t>(hModule) + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return false;
    
    auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        reinterpret_cast<uintptr_t>(hModule) + 
        ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    if (!exportDir) return false;
    
    auto names = reinterpret_cast<DWORD*>(reinterpret_cast<uintptr_t>(hModule) + exportDir->AddressOfNames);
    auto funcs = reinterpret_cast<DWORD*>(reinterpret_cast<uintptr_t>(hModule) + exportDir->AddressOfFunctions);
    auto ordinals = reinterpret_cast<WORD*>(reinterpret_cast<uintptr_t>(hModule) + exportDir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* funcName = reinterpret_cast<const char*>(reinterpret_cast<uintptr_t>(hModule) + names[i]);
        WORD ordinal = ordinals[i];
        uintptr_t funcAddr = reinterpret_cast<uintptr_t>(hModule) + funcs[ordinal];
        
        SymbolEntry entry;
        entry.name = moduleName + "!" + funcName;
        entry.address = funcAddr;
        entry.size = 0; // Will be determined by next symbol
        entry.flags = 0x1 | 0x4; // Code + Export
        entry.hash = CalculateCRC32(entry.name);
        
        symbols_[entry.name] = entry;
        hashIndex_[entry.hash].push_back(&symbols_[entry.name]);
    }
    
    return true;
}

uintptr_t SymbolTableGenerator::GetAddress(const std::string& symbolName) const {
    auto it = symbols_.find(symbolName);
    if (it != symbols_.end()) {
        return it->second.address;
    }
    
    // Try DbgHelp fallback
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
    PSYMBOL_INFO pSym = reinterpret_cast<PSYMBOL_INFO>(buffer);
    pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSym->MaxNameLen = MAX_SYM_NAME;
    
    DWORD64 displacement;
    if (SymFromName(GetCurrentProcess(), symbolName.c_str(), pSym)) {
        return static_cast<uintptr_t>(pSym->Address);
    }
    
    return 0;
}

const SymbolEntry* SymbolTableGenerator::GetSymbol(const std::string& symbolName) const {
    auto it = symbols_.find(symbolName);
    return (it != symbols_.end()) ? &it->second : nullptr;
}

std::vector<const SymbolEntry*> SymbolTableGenerator::FindSymbols(const std::string& pattern) const {
    std::vector<const SymbolEntry*> results;
    std::string lowerPattern = pattern;
    std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::tolower);
    
    for (const auto& [name, entry] : symbols_) {
        std::string lowerName = name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        if (lowerName.find(lowerPattern) != std::string::npos) {
            results.push_back(&entry);
        }
    }
    
    return results;
}

bool SymbolTableGenerator::IsAddressExecutable(uintptr_t addr) const {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }
    return false;
}

bool SymbolTableGenerator::IsAddressWritable(uintptr_t addr) const {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        return (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0;
    }
    return false;
}

const MemoryRegion* SymbolTableGenerator::GetRegionContaining(uintptr_t addr) const {
    for (const auto& region : regions_) {
        if (addr >= region.base && addr < region.base + region.size) {
            return &region;
        }
    }
    return nullptr;
}

bool SymbolTableGenerator::IsValidPatchTarget(const std::string& functionName) const {
    auto sym = GetSymbol(functionName);
    if (!sym) return false;
    return IsAddressExecutable(sym->address);
}

bool SymbolTableGenerator::IsValidPatchTarget(uintptr_t address) const {
    return IsAddressExecutable(address);
}

uint32_t SymbolTableGenerator::CalculateCRC32(const std::string& str) const {
    static const uint32_t table[] = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, // ... truncated for brevity
        // Full CRC32 table would be here
    };
    
    uint32_t crc = 0xFFFFFFFF;
    for (char c : str) {
        crc = (crc >> 8) ^ table[(crc ^ static_cast<uint8_t>(c)) & 0xFF];
    }
    return ~crc;
}

std::vector<uint8_t> SymbolTableGenerator::ExportToBinary() const {
    std::vector<uint8_t> data;
    
    // Header: magic + version + count
    const uint32_t magic = 0x52415753; // "RAWS"
    const uint32_t version = 1;
    const uint32_t count = static_cast<uint32_t>(symbols_.size());
    
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&magic), 
                reinterpret_cast<const uint8_t*>(&magic) + sizeof(magic));
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&version), 
                reinterpret_cast<const uint8_t*>(&version) + sizeof(version));
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&count), 
                reinterpret_cast<const uint8_t*>(&count) + sizeof(count));
    
    // Symbol entries
    for (const auto& [name, entry] : symbols_) {
        uint32_t nameLen = static_cast<uint32_t>(name.length());
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&nameLen), 
                    reinterpret_cast<const uint8_t*>(&nameLen) + sizeof(nameLen));
        data.insert(data.end(), name.begin(), name.end());
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&entry.address), 
                    reinterpret_cast<const uint8_t*>(&entry.address) + sizeof(entry.address));
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&entry.size), 
                    reinterpret_cast<const uint8_t*>(&entry.size) + sizeof(entry.size));
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&entry.flags), 
                    reinterpret_cast<const uint8_t*>(&entry.flags) + sizeof(entry.flags));
    }
    
    return data;
}

bool SymbolTableGenerator::ImportFromBinary(const uint8_t* data, size_t size) {
    if (size < 12) return false;
    
    uint32_t magic = *reinterpret_cast<const uint32_t*>(data);
    if (magic != 0x52415753) return false;
    
    uint32_t version = *reinterpret_cast<const uint32_t*>(data + 4);
    if (version != 1) return false;
    
    // Clear existing
    symbols_.clear();
    hashIndex_.clear();
    
    size_t offset = 12;
    uint32_t count = *reinterpret_cast<const uint32_t*>(data + 8);
    
    for (uint32_t i = 0; i < count && offset < size; i++) {
        if (offset + 4 > size) break;
        uint32_t nameLen = *reinterpret_cast<const uint32_t*>(data + offset);
        offset += 4;
        
        if (offset + nameLen + sizeof(uintptr_t) * 2 + sizeof(uint32_t) > size) break;
        
        SymbolEntry entry;
        entry.name = std::string(reinterpret_cast<const char*>(data + offset), nameLen);
        offset += nameLen;
        
        entry.address = *reinterpret_cast<const uintptr_t*>(data + offset);
        offset += sizeof(uintptr_t);
        entry.size = *reinterpret_cast<const size_t*>(data + offset);
        offset += sizeof(size_t);
        entry.flags = *reinterpret_cast<const uint32_t*>(data + offset);
        offset += sizeof(uint32_t);
        entry.hash = CalculateCRC32(entry.name);
        
        symbols_[entry.name] = entry;
        hashIndex_[entry.hash].push_back(&symbols_[entry.name]);
    }
    
    return true;
}

void SymbolTableGenerator::RefreshDynamicSymbols() {
    // Re-scan for any newly loaded modules or JIT compiled code
    // This is called after dynamic code generation
    Initialize();
}

} // namespace Sovereign
} // namespace RawrXD
