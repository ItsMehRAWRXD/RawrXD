// cli_integration_patch.cpp - Patch to add to d:\rawrxd\src\cli_shell.cpp
// Add these sections to the existing cli_shell.cpp file

// ============================================================================
// SECTION 1: Add to includes (near top of file, after other includes)
// ============================================================================
/*
#define RAWRXD_CLI_BUILD
#include "browser/BrowserIntegration.hpp"
*/

// ============================================================================
// SECTION 2: Add to Init function (in CLIState initialization)
// ============================================================================
/*
void CLI_Init() {
    // ... existing init code ...
    
    // Initialize browser
    RAWRXD_BROWSER_CLI_INIT();
}
*/

// ============================================================================
// SECTION 3: Add to Shutdown function
// ============================================================================
/*
void CLI_Shutdown() {
    // ... existing shutdown code ...
    
    // Shutdown browser
    RAWRXD_BROWSER_CLI_SHUTDOWN();
}
*/

// ============================================================================
// SECTION 4: Add to command dispatcher (where you handle !commands)
// ============================================================================
/*
void ProcessCommand(const std::string& input) {
    // Parse command
    std::string cmd = ParseCommand(input);
    std::string args = ParseArgs(input);
    
    // Try browser commands first
    if (RAWRXD_BROWSER_CLI_HANDLE(cmd, args)) {
        return; // Browser handled it
    }
    
    // ... existing command handling ...
}
*/

// ============================================================================
// SECTION 5: Add to help command
// ============================================================================
/*
void CmdHelp() {
    // ... existing help ...
    
    std::cout << "\n=== Browser Commands ===" << std::endl;
    std::cout << RAWRXD_BROWSER_CLI_HELP << std::endl;
}
*/

// ============================================================================
// SECTION 6: Add browser commands to command table
// ============================================================================
/*
// In your command registration or dispatch table:
CommandTable commands[] = {
    // ... existing commands ...
    {"browser", CmdBrowser, "Navigate to URL"},
    {"back", CmdBrowserBack, "Go back"},
    {"forward", CmdBrowserForward, "Go forward"},
    {"reload", CmdBrowserReload, "Reload page"},
    {"stop", CmdBrowserStop, "Stop loading"},
    {"docs", CmdDocs, "Show documentation"},
    {"github", CmdGitHub, "Open GitHub"},
    {"search", CmdSearch, "Search web"},
    {"fetch", CmdFetch, "HTTP GET request"},
    {"post", CmdPost, "HTTP POST request"},
    // ...
};
*/
