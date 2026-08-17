// BrowserCLI.hpp - Browser Commands for RawrXD CLI
// CLI integration for the zero-dependency browser

#ifndef RAWRXD_BROWSER_CLI_HPP
#define RAWRXD_BROWSER_CLI_HPP

#include <string>
#include <vector>
#include <functional>

namespace RawrXD {

// Browser command handlers for CLI
namespace BrowserCLI {
    // Command handlers - return true if command was handled
    bool HandleCommand(const std::string& cmd, const std::string& args);
    
    // Individual commands
    void CmdBrowser(const std::string& args);
    void CmdBrowserBack(const std::string& args);
    void CmdBrowserForward(const std::string& args);
    void CmdBrowserReload(const std::string& args);
    void CmdBrowserStop(const std::string& args);
    void CmdDocs(const std::string& args);
    void CmdGitHub(const std::string& args);
    void CmdSearch(const std::string& args);
    void CmdFetch(const std::string& args); // HTTP GET from CLI
    void CmdPost(const std::string& args);  // HTTP POST from CLI
    
    // Browser state
    struct BrowserState {
        std::string currentURL;
        std::string pageTitle;
        std::vector<std::string> history;
        int historyIndex{-1};
        bool isLoading{false};
        bool headlessMode{true}; // CLI runs browser in headless mode
    };
    
    BrowserState& GetState();
    
    // Initialize CLI browser module
    void Init();
    void Shutdown();
    
    // Get help text
    std::string GetHelpText();
    
    // Command registration for CLI shell
    void RegisterCommands();
}

} // namespace RawrXD

#endif // RAWRXD_BROWSER_CLI_HPP
