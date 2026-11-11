/*=============================================================================
 * Command Palette Bridge - C-Compatible Structure for MASM Interop
 * 
 * CRITICAL: This structure must match exactly between C++ and MASM.
 * The std::vector<CommandPaletteItem> in Win32IDE.h CANNOT be read
 * directly from MASM because std::string is a complex C++ object.
 * 
 * Use this flat, C-compatible structure for MASM interop instead.
 *===========================================================================*/
#pragma once

#ifndef COMMAND_PALETTE_BRIDGE_H
#define COMMAND_PALETTE_BRIDGE_H

#include <cstdint>
#include <cstring>

// Ensure C-compatible layout
#pragma pack(push, 8)

/*=============================================================================
 * CommandPaletteEntry - Flat C structure for MASM interop
 * 
 * This replaces the C++ CommandPaletteItem for MASM traversal.
 * All strings are raw const char* pointers (not std::string objects).
 * 
 * Memory Layout (verified for MSVC x64):
 *   Offset 0:   id          (int32, 4 bytes)
 *   Offset 4:   _padding    (4 bytes for alignment)
 *   Offset 8:   name        (const char*, 8 bytes)
 *   Offset 16:  shortcut    (const char*, 8 bytes)
 *   Offset 24:  category    (const char*, 8 bytes)
 *   Total: 32 bytes
 *===========================================================================*/
struct alignas(8) CommandPaletteEntry {
    int32_t     id;             // +0  (4 bytes)
    int32_t     _padding;       // +4  (4 bytes explicit padding)
    const char* name;           // +8  (8 bytes)
    const char* shortcut;       // +16 (8 bytes)
    const char* category;       // +24 (8 bytes)
    
    // Constructor for easy conversion from CommandPaletteItem
    CommandPaletteEntry() = default;
    
    CommandPaletteEntry(int32_t _id, const char* _name, 
                        const char* _shortcut, const char* _category)
        : id(_id)
        , _padding(0)
        , name(_name)
        , shortcut(_shortcut)
        , category(_category)
    {}
};

#pragma pack(pop)

// Compile-time verification
static_assert(sizeof(CommandPaletteEntry) == 32, 
    "CommandPaletteEntry must be exactly 32 bytes!");
static_assert(alignof(CommandPaletteEntry) == 8,
    "CommandPaletteEntry must be 8-byte aligned!");
static_assert(offsetof(CommandPaletteEntry, id) == 0,
    "id must be at offset 0!");
static_assert(offsetof(CommandPaletteEntry, name) == 8,
    "name must be at offset 8!");
static_assert(offsetof(CommandPaletteEntry, shortcut) == 16,
    "shortcut must be at offset 16!");
static_assert(offsetof(CommandPaletteEntry, category) == 24,
    "category must be at offset 24!");

// Constants for MASM (use these in your ASM code)
constexpr uint32_t COMMAND_ENTRY_SIZE = 32;      // Use: mov rcx, 32
constexpr uint32_t NAME_PTR_OFFSET = 8;          // Use: [rdi+8]
constexpr uint32_t SHORTCUT_PTR_OFFSET = 16;     // Use: [rdi+16]
constexpr uint32_t CATEGORY_PTR_OFFSET = 24;     // Use: [rdi+24]
constexpr uint32_t MAX_COMMANDS = 183;

/*=============================================================================
 * CommandPaletteBridge - Converts C++ vector to C-compatible array
 * 
 * Usage:
 *   auto bridge = CommandPaletteBridge::FromVector(m_commandRegistry);
 *   // Pass bridge.data() to MASM
 *===========================================================================*/
class CommandPaletteBridge {
public:
    // Convert std::vector<CommandPaletteItem> to flat array
    template<typename T>
    static std::vector<CommandPaletteEntry> FromVector(const std::vector<T>& items) {
        std::vector<CommandPaletteEntry> result;
        result.reserve(items.size());
        
        for (const auto& item : items) {
            // Extract C strings from std::string
            const char* name = item.name.c_str();
            const char* shortcut = item.shortcut.c_str();
            const char* category = item.category.c_str();
            
            result.emplace_back(item.id, name, shortcut, category);
        }
        
        return result;
    }
    
    // Create a flat array suitable for MASM interop
    // The returned pointer is stable for the lifetime of the returned vector
    static const CommandPaletteEntry* GetFlatArray(
        const std::vector<CommandPaletteEntry>& entries) {
        return entries.empty() ? nullptr : entries.data();
    }
    
    // Validate the flat array before passing to MASM
    static bool Validate(const CommandPaletteEntry* entries, size_t count) {
        if (!entries || count == 0) return false;
        
        for (size_t i = 0; i < count; i++) {
            const auto& entry = entries[i];
            
            // Check ID is valid
            if (entry.id == 0) {
                OutputDebugStringA("ERROR: Command entry has null ID\n");
                return false;
            }
            
            // Check name pointer
            if (!entry.name) {
                OutputDebugStringA("ERROR: Command entry has null name\n");
                return false;
            }
            
            // Check first character is printable
            char firstChar = entry.name[0];
            if (firstChar < 0x20 || firstChar > 0x7E) {
                char msg[256];
                sprintf_s(msg, "ERROR: Command[%zu] name starts with invalid byte 0x%02X\n", 
                         i, (unsigned char)firstChar);
                OutputDebugStringA(msg);
                return false;
            }
        }
        
        return true;
    }
    
    // Debug dump of registry contents
    static void Dump(const CommandPaletteEntry* entries, size_t count, 
                     size_t maxEntries = 5) {
        char msg[512];
        OutputDebugStringA("=== Command Palette Bridge Dump ===\n");
        
        size_t entriesToDump = (count < maxEntries) ? count : maxEntries;
        for (size_t i = 0; i < entriesToDump; i++) {
            const auto& entry = entries[i];
            
            sprintf_s(msg, "Entry[%zu] @ 0x%p:\n", i, &entry);
            OutputDebugStringA(msg);
            
            sprintf_s(msg, "  id: %d (0x%08X)\n", entry.id, entry.id);
            OutputDebugStringA(msg);
            
            sprintf_s(msg, "  name: 0x%p -> '%s'\n", 
                     (void*)entry.name, entry.name ? entry.name : "(null)");
            OutputDebugStringA(msg);
            
            sprintf_s(msg, "  shortcut: 0x%p -> '%s'\n",
                     (void*)entry.shortcut, entry.shortcut ? entry.shortcut : "");
            OutputDebugStringA(msg);
            
            sprintf_s(msg, "  category: 0x%p -> '%s'\n",
                     (void*)entry.category, entry.category ? entry.category : "");
            OutputDebugStringA(msg);
        }
        
        if (count > maxEntries) {
            sprintf_s(msg, "... (%zu more entries)\n", count - maxEntries);
            OutputDebugStringA(msg);
        }
        
        OutputDebugStringA("=== End Dump ===\n");
    }
};

#endif // COMMAND_PALETTE_BRIDGE_H
