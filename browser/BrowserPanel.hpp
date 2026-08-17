// BrowserPanel.hpp - Browser Integration for RawrXD GUI IDE
// Embeds the zero-dependency browser as a dockable panel

#ifndef RAWRXD_BROWSER_PANEL_HPP
#define RAWRXD_BROWSER_PANEL_HPP

#include "RawrXD_Browser.h"
#include <windows.h>
#include <string>
#include <functional>

namespace RawrXD {

// Browser panel integration for the IDE
class BrowserPanel {
public:
    static void Init();
    static void Shutdown();
    static void Toggle();
    static void Show();
    static void Hide();
    static bool IsVisible();
    static int Id() { return PANEL_ID; }
    
    // Browser control
    static void Navigate(const std::string& url);
    static void NavigateBack();
    static void NavigateForward();
    static void Reload();
    static void Stop();
    
    // Getters
    static std::string GetCurrentURL();
    static std::string GetPageTitle();
    static bool IsLoading();
    
    // Window handle for docking
    static HWND GetHWND();
    
    // Menu integration
    static void RegisterHotkeys();
    
private:
    static constexpr int PANEL_ID = 0xB100; // Unique panel ID
    static inline BrowserWindow* s_browser = nullptr;
    static inline bool s_initialized = false;
    static inline bool s_visible = false;
    
    static void CreateBrowser();
};

// Browser commands for IDE integration
namespace BrowserCommands {
    void OpenURL(const std::string& url);
    void OpenDocumentation();
    void OpenGitHub();
    void OpenSettings();
    void Search(const std::string& query);
}

} // namespace RawrXD

#endif // RAWRXD_BROWSER_PANEL_HPP
