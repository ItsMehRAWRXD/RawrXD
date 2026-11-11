/*=============================================================================
 * Command Registry - Cross-Platform Structure Definition
 * Ensures C++ and ASM agree on structure layout
 *===========================================================================*/
#pragma once

#ifndef RAWRXD_COMMAND_REGISTRY_H
#define RAWRXD_COMMAND_REGISTRY_H

#include <cstdint>
#include <windows.h>

// Force 8-byte alignment to match ASM ALIGN(8)
#pragma pack(push, 8)

/*=============================================================================
 * CommandEntry - Single command in the registry
 * 
 * CRITICAL: This structure must match exactly with ASM definition
 * Size: 40 bytes (not 36!)
 * Alignment: 8-byte
 *===========================================================================*/
struct alignas(8) CommandEntry {
    uint32_t    commandId;      // +0  (4 bytes)
    uint32_t    _padding;       // +4  (4 bytes) - explicit padding for alignment
    const char* namePtr;        // +8  (8 bytes) - aligned to 8-byte boundary
    const char* shortcutPtr;    // +16 (8 bytes)
    const char* categoryPtr;    // +24 (8 bytes)
    void*       handlerPtr;     // +32 (8 bytes)
    
    // Total: 40 bytes
    
    CommandEntry() = default;
    
    CommandEntry(uint32_t id, const char* name, const char* shortcut, const char* category)
        : commandId(id)
        , _padding(0)
        , namePtr(name)
        , shortcutPtr(shortcut)
        , categoryPtr(category)
        , handlerPtr(nullptr)
    {}
};

#pragma pack(pop)

// Verify structure size at compile time
static_assert(sizeof(CommandEntry) == 40, "CommandEntry must be exactly 40 bytes!");
static_assert(alignof(CommandEntry) == 8, "CommandEntry must be 8-byte aligned!");
static_assert(offsetof(CommandEntry, namePtr) == 8, "namePtr must be at offset 8!");
static_assert(offsetof(CommandEntry, shortcutPtr) == 16, "shortcutPtr must be at offset 16!");
static_assert(offsetof(CommandEntry, categoryPtr) == 24, "categoryPtr must be at offset 24!");
static_assert(offsetof(CommandEntry, handlerPtr) == 32, "handlerPtr must be at offset 32!");

/*=============================================================================
 * Command Registry Constants
 *===========================================================================*/
constexpr uint32_t COMMAND_ENTRY_SIZE = 40;  // Use this in ASM with "mov rcx, 40"
constexpr uint32_t COMMAND_NAME_OFFSET = 8;   // Offset of namePtr
constexpr uint32_t MAX_COMMANDS = 183;        // Your registry size

/*=============================================================================
 * Debug Helper Functions
 *===========================================================================*/
namespace CommandRegistryDebug {
    // Validate the entire registry for corruption
    inline bool ValidateRegistry(const CommandEntry* registry, uint32_t count) {
        for (uint32_t i = 0; i < count; i++) {
            const CommandEntry& entry = registry[i];
            
            // Check ID is valid
            if (entry.commandId == 0) {
                OutputDebugStringA("ERROR: Command entry has null ID\n");
                return false;
            }
            
            // Check name pointer
            if (entry.namePtr == nullptr) {
                OutputDebugStringA("ERROR: Command entry has null namePtr\n");
                return false;
            }
            
            // Check first character is printable
            char firstChar = entry.namePtr[0];
            if (firstChar < 0x20 || firstChar > 0x7E) {
                char msg[256];
                sprintf_s(msg, "ERROR: Command[%u] name starts with invalid byte 0x%02X\n", 
                         i, (unsigned char)firstChar);
                OutputDebugStringA(msg);
                return false;
            }
            
            // Verify expected characters for known commands
            if (entry.commandId >= 1001 && entry.commandId <= 1100) {
                // File commands should start with 'F' ("File: ...")
                if (firstChar != 'F' && firstChar != 'N') {  // "New File" etc.
                    char msg[256];
                    sprintf_s(msg, "WARNING: Command[%u] ID=%u name='%s' unexpected first char\n",
                             i, entry.commandId, entry.namePtr);
                    OutputDebugStringA(msg);
                }
            }
        }
        return true;
    }
    
    // Dump registry memory for debugging
    inline void DumpRegistryMemory(const CommandEntry* registry, uint32_t count, uint32_t maxEntries = 5) {
        char msg[512];
        OutputDebugStringA("=== Command Registry Memory Dump ===\n");
        
        uint32_t entriesToDump = (count < maxEntries) ? count : maxEntries;
        for (uint32_t i = 0; i < entriesToDump; i++) {
            const CommandEntry& entry = registry[i];
            sprintf_s(msg, "Entry[%u] @ 0x%p:\n", i, &entry);
            OutputDebugStringA(msg);
            
            sprintf_s(msg, "  commandId: %u (0x%08X)\n", entry.commandId, entry.commandId);
            OutputDebugStringA(msg);
            
            sprintf_s(msg, "  namePtr: 0x%p -> '%s'\n", entry.namePtr, 
                     entry.namePtr ? entry.namePtr : "(null)");
            OutputDebugStringA(msg);
            
            if (entry.namePtr) {
                // Show first 16 bytes of string memory
                sprintf_s(msg, "  name bytes: ");
                OutputDebugStringA(msg);
                for (int j = 0; j < 16 && entry.namePtr[j]; j++) {
                    sprintf_s(msg, "%02X ", (unsigned char)entry.namePtr[j]);
                    OutputDebugStringA(msg);
                }
                OutputDebugStringA("\n");
            }
        }
        OutputDebugStringA("=== End Memory Dump ===\n");
    }
}

/*=============================================================================
 * Example Command Registry Initialization
 *===========================================================================*/
inline void InitializeCommandRegistry(CommandEntry* registry, uint32_t& count) {
    uint32_t idx = 0;
    
    // File commands (1001-1100)
    registry[idx++] = CommandEntry(1001, "File: New File", "Ctrl+N", "File");
    registry[idx++] = CommandEntry(1002, "File: Open File", "Ctrl+O", "File");
    registry[idx++] = CommandEntry(1003, "File: Save", "Ctrl+S", "File");
    registry[idx++] = CommandEntry(1004, "File: Save As", "Ctrl+Shift+S", "File");
    registry[idx++] = CommandEntry(1005, "File: Save All", "", "File");
    registry[idx++] = CommandEntry(1006, "File: Close File", "Ctrl+W", "File");
    registry[idx++] = CommandEntry(1007, "File: New Folder", "", "File");  // The "lew Folde" culprit!
    registry[idx++] = CommandEntry(1008, "File: Install Extension", "", "File");  // The "nstal" culprit!
    
    // ... more commands to reach 183 total
    
    count = idx;
    
    // Validate immediately after initialization
    #ifdef _DEBUG
    CommandRegistryDebug::ValidateRegistry(registry, count);
    CommandRegistryDebug::DumpRegistryMemory(registry, count, 10);
    #endif
}

#endif // RAWRXD_COMMAND_REGISTRY_H
