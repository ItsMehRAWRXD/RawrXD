// BrowserIntegration.hpp - Integration hooks for CLI and GUI
// Include this in cli_shell.cpp and gui_main.cpp

#ifndef RAWRXD_BROWSER_INTEGRATION_HPP
#define RAWRXD_BROWSER_INTEGRATION_HPP

// CLI Integration
#ifdef RAWRXD_CLI_BUILD
    #include "BrowserCLI.hpp"
    
    // Call this from CLI initialization
    #define RAWRXD_BROWSER_CLI_INIT() RawrXD::BrowserCLI::Init()
    
    // Call this from CLI shutdown
    #define RAWRXD_BROWSER_CLI_SHUTDOWN() RawrXD::BrowserCLI::Shutdown()
    
    // Call this from command dispatcher
    #define RAWRXD_BROWSER_CLI_HANDLE(cmd, args) RawrXD::BrowserCLI::HandleCommand(cmd, args)
    
    // Browser commands help
    #define RAWRXD_BROWSER_CLI_HELP RawrXD::BrowserCLI::GetHelpText()
#endif

// GUI Integration
#ifdef RAWRXD_GUI_BUILD
    #include "BrowserPanel.hpp"
    
    // Call this from GUI initialization
    #define RAWRXD_BROWSER_GUI_INIT() RawrXD::BrowserPanel::Init()
    
    // Call this from GUI shutdown
    #define RAWRXD_BROWSER_GUI_SHUTDOWN() RawrXD::BrowserPanel::Shutdown()
    
    // Toggle browser panel
    #define RAWRXD_BROWSER_GUI_TOGGLE() RawrXD::BrowserPanel::Toggle()
    
    // Navigate to URL
    #define RAWRXD_BROWSER_GUI_NAVIGATE(url) RawrXD::BrowserPanel::Navigate(url)
#endif

// Common integration (works in both CLI and GUI)
#include "RawrXD_Browser.h"

namespace RawrXD {
namespace BrowserIntegration {
    // Version info
    const char* GetBrowserVersion();
    
    // Check if browser is available
    bool IsBrowserAvailable();
    
    // Get browser capabilities
    struct BrowserCapabilities {
        bool httpSupport;
        bool httpsSupport;
        bool htmlParsing;
        bool cssSupport;
        bool javascriptSupport;
        bool imageRendering;
    };
    BrowserCapabilities GetCapabilities();
}
}

#endif // RAWRXD_BROWSER_INTEGRATION_HPP
