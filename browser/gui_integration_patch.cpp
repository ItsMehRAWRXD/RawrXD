// gui_integration_patch.cpp - Patch to add to d:\rawrxd\src\gui_main.cpp
// Add these sections to the existing gui_main.cpp file

// ============================================================================
// SECTION 1: Add to includes (near top of file)
// ============================================================================
/*
#define RAWRXD_GUI_BUILD
#include "browser/BrowserIntegration.hpp"
*/

// ============================================================================
// SECTION 2: Add to GUIMain::initialize() method
// ============================================================================
/*
std::expected<void, std::string> GUIMain::initialize(HINSTANCE hInstance) {
    // ... existing initialization code ...
    
    // Initialize browser panel
    RAWRXD_BROWSER_GUI_INIT();
    
    // ... rest of initialization ...
    return {};
}
*/

// ============================================================================
// SECTION 3: Add to GUIMain::shutdown() method
// ============================================================================
/*
void GUIMain::shutdown() {
    // ... existing shutdown code ...
    
    // Shutdown browser panel
    RAWRXD_BROWSER_GUI_SHUTDOWN();
}
*/

// ============================================================================
// SECTION 4: Add to menu creation (in createMenus() function)
// ============================================================================
/*
void GUIMain::createMenus() {
    // ... existing menu creation ...
    
    // Add Browser menu
    HMENU hBrowserMenu = CreatePopupMenu();
    AppendMenu(hBrowserMenu, MF_STRING, ID_BROWSER_TOGGLE, L"&Toggle Browser\tCtrl+Shift+B");
    AppendMenu(hBrowserMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenu(hBrowserMenu, MF_STRING, ID_BROWSER_BACK, L"&Back\tAlt+Left");
    AppendMenu(hBrowserMenu, MF_STRING, ID_BROWSER_FORWARD, L"&Forward\tAlt+Right");
    AppendMenu(hBrowserMenu, MF_STRING, ID_BROWSER_RELOAD, L"&Reload\tF5");
    AppendMenu(hBrowserMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenu(hBrowserMenu, MF_STRING, ID_BROWSER_DOCS, L"&Documentation\tCtrl+Shift+D");
    AppendMenu(hBrowserMenu, MF_STRING, ID_BROWSER_GITHUB, L"&GitHub\tCtrl+Shift+G");
    
    AppendMenu(hMenuBar, MF_POPUP, (UINT_PTR)hBrowserMenu, L"&Browser");
}
*/

// ============================================================================
// SECTION 5: Add to window procedure (WndProc)
// ============================================================================
/*
LRESULT CALLBACK GUIMain::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        // ... existing cases ...
        
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                // ... existing commands ...
                
                case ID_BROWSER_TOGGLE:
                    RAWRXD_BROWSER_GUI_TOGGLE();
                    return 0;
                    
                case ID_BROWSER_BACK:
                    RawrXD::BrowserPanel::NavigateBack();
                    return 0;
                    
                case ID_BROWSER_FORWARD:
                    RawrXD::BrowserPanel::NavigateForward();
                    return 0;
                    
                case ID_BROWSER_RELOAD:
                    RawrXD::BrowserPanel::Reload();
                    return 0;
                    
                case ID_BROWSER_DOCS:
                    RawrXD::BrowserCommands::OpenDocumentation();
                    return 0;
                    
                case ID_BROWSER_GITHUB:
                    RawrXD::BrowserCommands::OpenGitHub();
                    return 0;
            }
            break;
            
        // ... rest of window procedure ...
    }
}
*/

// ============================================================================
// SECTION 6: Add menu IDs to resource.h or gui_main.h
// ============================================================================
/*
// Browser menu commands
#define ID_BROWSER_TOGGLE       4001
#define ID_BROWSER_BACK         4002
#define ID_BROWSER_FORWARD      4003
#define ID_BROWSER_RELOAD       4004
#define ID_BROWSER_STOP         4005
#define ID_BROWSER_DOCS         4006
#define ID_BROWSER_GITHUB       4007
*/

// ============================================================================
// SECTION 7: Add to IDEEntry.cpp Init() function
// ============================================================================
/*
void IDEEntry::Init() {
    // ... existing init code ...
    
    // Initialize browser panel
    RawrXD::BrowserPanel::Init();
    
    // Register browser hotkeys
    HotkeySystem::Register("Ctrl+Shift+B", [](){ RawrXD::BrowserPanel::Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+D", [](){ RawrXD::BrowserCommands::OpenDocumentation(); });
    HotkeySystem::Register("Ctrl+Shift+G", [](){ RawrXD::BrowserCommands::OpenGitHub(); });
    
    // Add browser panel to docking layout
    DockingLayout::Add(RawrXD::BrowserPanel::Id(), DockingLayout::Right);
    
    // ... rest of init ...
}
*/

// ============================================================================
// SECTION 8: Add to IDEEntry.cpp Shutdown
// ============================================================================
/*
void IDEEntry::Shutdown() {
    // ... existing shutdown code ...
    
    // Shutdown browser panel
    RawrXD::BrowserPanel::Shutdown();
}
*/
