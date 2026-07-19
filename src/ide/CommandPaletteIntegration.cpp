/*=============================================================================
 * Command Palette Integration - Bridges C++ std::vector to MASM
 * 
 * This file demonstrates how to safely pass the command registry from
 * C++ (std::vector<CommandPaletteItem>) to MASM (flat C array).
 *===========================================================================*/

#include "CommandPaletteBridge.h"
#include <windows.h>
#include <vector>
#include <string>

// Forward declarations for MASM functions
extern "C" {
    // Render the command palette
    // Parameters: HDC, entries pointer, entry count, client rect
    void RenderCommandPalette(HDC hdc, const CommandPaletteEntry* entries, 
                               int count, const RECT* clientRect);
    
    // Validate before rendering
    // Returns: 0 = valid, 1 = error
    int ValidateCommandPalette(const CommandPaletteEntry* entries, int count);
}

// Example integration with Win32IDE
class CommandPaletteRenderer {
public:
    // Convert and render the command palette
    template<typename T>
    void Render(HDC hdc, const std::vector<T>& commandItems, 
                const RECT& clientRect) {
        
        // Step 1: Convert C++ vector to flat C array
        auto flatEntries = CommandPaletteBridge::FromVector(commandItems);
        
        if (flatEntries.empty()) {
            OutputDebugStringA("CommandPaletteRenderer: No entries to render\n");
            return;
        }
        
        // Step 2: Validate before passing to MASM
        if (!CommandPaletteBridge::Validate(flatEntries.data(), flatEntries.size())) {
            OutputDebugStringA("CommandPaletteRenderer: Validation failed!\n");
            return;
        }
        
        // Step 3: Debug dump (optional, remove in release)
        #ifdef _DEBUG
        CommandPaletteBridge::Dump(flatEntries.data(), flatEntries.size(), 5);
        #endif
        
        // Step 4: Call MASM renderer
        // CRITICAL: flatEntries must remain alive during the call!
        // The MASM code reads directly from flatEntries.data()
        RenderCommandPalette(hdc, flatEntries.data(), 
                            static_cast<int>(flatEntries.size()), 
                            &clientRect);
        
        // Note: flatEntries is destroyed here, but that's OK because
        // the MASM renderer has finished reading from it.
        // If you need persistent storage, make flatEntries a member variable.
    }
    
    // Persistent storage version (for multiple render passes)
    template<typename T>
    void UpdateEntries(const std::vector<T>& commandItems) {
        m_flatEntries = CommandPaletteBridge::FromVector(commandItems);
        m_entriesValid = CommandPaletteBridge::Validate(
            m_flatEntries.data(), m_flatEntries.size());
    }
    
    void RenderPersistent(HDC hdc, const RECT& clientRect) {
        if (!m_entriesValid || m_flatEntries.empty()) {
            return;
        }
        
        RenderCommandPalette(hdc, m_flatEntries.data(),
                            static_cast<int>(m_flatEntries.size()),
                            &clientRect);
    }
    
private:
    std::vector<CommandPaletteEntry> m_flatEntries;
    bool m_entriesValid = false;
};

/*=============================================================================
 * Compile-Time Verification
 * These assertions ensure the C++ and ASM structures match.
 *===========================================================================*/

// Verify structure size matches MASM expectation
static_assert(sizeof(CommandPaletteEntry) == 32,
    "C++ structure size must match MASM (32 bytes)!");

// Verify offsets match MASM constants
static_assert(offsetof(CommandPaletteEntry, id) == 0,
    "id offset must be 0!");
static_assert(offsetof(CommandPaletteEntry, name) == 8,
    "name offset must be 8 (matches NAME_PTR_OFFSET in ASM)!");
static_assert(offsetof(CommandPaletteEntry, shortcut) == 16,
    "shortcut offset must be 16 (matches SHORTCUT_PTR_OFFSET in ASM)!");
static_assert(offsetof(CommandPaletteEntry, category) == 24,
    "category offset must be 24 (matches CATEGORY_PTR_OFFSET in ASM)!");

/*=============================================================================
 * Usage Example
 *===========================================================================*/

/*
// In your Win32IDE class:

class Win32IDE {
    // ... existing members ...
    
    CommandPaletteRenderer m_paletteRenderer;
    
    void OnCommandPalettePaint(HDC hdc, const RECT& clientRect) {
        // Option 1: One-shot render (converts every paint)
        m_paletteRenderer.Render(hdc, m_commandRegistry, clientRect);
        
        // Option 2: Persistent (convert once, render many)
        // Call UpdateEntries() when registry changes
        // Call RenderPersistent() in WM_PAINT
    }
    
    void buildCommandRegistry() {
        // ... populate m_commandRegistry ...
        
        // Update the flat array for MASM
        m_paletteRenderer.UpdateEntries(m_commandRegistry);
    }
};
*/

/*=============================================================================
 * Build Instructions
 * 
 * 1. Assemble the MASM file:
 *    ml64.exe /c /Zi CommandPaletteRenderer.asm
 * 
 * 2. Link with your project:
 *    link ... CommandPaletteRenderer.obj ...
 * 
 * 3. Include in C++:
 *    #include "CommandPaletteBridge.h"
 *    #include "CommandPaletteIntegration.cpp"
 * 
 * 4. Call the renderer from your WM_PAINT handler
 *===========================================================================*/
