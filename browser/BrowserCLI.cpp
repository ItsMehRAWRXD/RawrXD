// BrowserCLI.cpp - Browser Commands Implementation for RawrXD CLI

#include "BrowserCLI.hpp"
#include "RawrXD_Browser.h"
#include <iostream>
#include <thread>
#include <chrono>

namespace RawrXD {

static BrowserCLI::BrowserState g_browserState;
static std::unique_ptr<NetworkEngine> g_networkEngine;

void BrowserCLI::Init() {
    std::cout << "[BrowserCLI] Initializing..." << std::endl;
    
    g_networkEngine = std::make_unique<NetworkEngine>();
    if (!g_networkEngine->Initialize()) {
        std::cerr << "[BrowserCLI] Failed to initialize network engine" << std::endl;
    }
    
    RegisterCommands();
    
    std::cout << "[BrowserCLI] Initialized. Type !browser help for commands." << std::endl;
}

void BrowserCLI::Shutdown() {
    if (g_networkEngine) {
        g_networkEngine->Shutdown();
        g_networkEngine.reset();
    }
}

BrowserCLI::BrowserState& BrowserCLI::GetState() {
    return g_browserState;
}

bool BrowserCLI::HandleCommand(const std::string& cmd, const std::string& args) {
    if (cmd == "browser" || cmd == "!browser") {
        CmdBrowser(args);
        return true;
    }
    if (cmd == "back" || cmd == "!back") {
        CmdBrowserBack(args);
        return true;
    }
    if (cmd == "forward" || cmd == "!forward") {
        CmdBrowserForward(args);
        return true;
    }
    if (cmd == "reload" || cmd == "!reload") {
        CmdBrowserReload(args);
        return true;
    }
    if (cmd == "stop" || cmd == "!stop") {
        CmdBrowserStop(args);
        return true;
    }
    if (cmd == "docs" || cmd == "!docs") {
        CmdDocs(args);
        return true;
    }
    if (cmd == "github" || cmd == "!github") {
        CmdGitHub(args);
        return true;
    }
    if (cmd == "search" || cmd == "!search") {
        CmdSearch(args);
        return true;
    }
    if (cmd == "fetch" || cmd == "!fetch") {
        CmdFetch(args);
        return true;
    }
    if (cmd == "post" || cmd == "!post") {
        CmdPost(args);
        return true;
    }
    return false;
}

void BrowserCLI::CmdBrowser(const std::string& args) {
    if (args.empty() || args == "help") {
        std::cout << GetHelpText() << std::endl;
        return;
    }
    
    if (args == "status") {
        std::cout << "Current URL: " << (g_browserState.currentURL.empty() ? "(none)" : g_browserState.currentURL) << std::endl;
        std::cout << "Page Title: " << (g_browserState.pageTitle.empty() ? "(none)" : g_browserState.pageTitle) << std::endl;
        std::cout << "History: " << g_browserState.historyIndex + 1 << "/" << g_browserState.history.size() << std::endl;
        return;
    }
    
    if (args == "history") {
        std::cout << "Browser History:" << std::endl;
        for (size_t i = 0; i < g_browserState.history.size(); ++i) {
            std::cout << (i == static_cast<size_t>(g_browserState.historyIndex) ? " -> " : "    ");
            std::cout << i + 1 << ". " << g_browserState.history[i] << std::endl;
        }
        return;
    }
    
    // Navigate to URL
    std::string url = args;
    if (!BrowserUtils::IsAbsoluteURL(url)) {
        url = "https://" + url;
    }
    
    std::cout << "Navigating to: " << url << std::endl;
    
    if (!g_networkEngine) {
        std::cerr << "Network engine not initialized!" << std::endl;
        return;
    }
    
    g_browserState.isLoading = true;
    HTTPResponse response = g_networkEngine->Get(url);
    g_browserState.isLoading = false;
    
    if (response.success) {
        g_browserState.currentURL = url;
        g_browserState.pageTitle = url; // TODO: Parse title from HTML
        
        // Add to history
        if (g_browserState.historyIndex < 0 || 
            g_browserState.history[static_cast<size_t>(g_browserState.historyIndex)] != url) {
            if (g_browserState.historyIndex + 1 < static_cast<int>(g_browserState.history.size())) {
                g_browserState.history.resize(static_cast<size_t>(g_browserState.historyIndex) + 1);
            }
            g_browserState.history.push_back(url);
            g_browserState.historyIndex++;
        }
        
        // Display content (truncated for CLI)
        std::cout << "\n=== " << url << " ===" << std::endl;
        std::cout << "Status: " << response.statusCode << std::endl;
        std::cout << "Content-Type: " << response.contentType << std::endl;
        std::cout << "Length: " << response.body.length() << " bytes" << std::endl;
        
        // Show text content if HTML
        if (response.contentType.find("text/html") != std::string::npos) {
            HTMLParser parser;
            std::string text = parser.ExtractText(response.body);
            std::cout << "\n--- Text Content ---" << std::endl;
            
            // Limit output
            if (text.length() > 2000) {
                std::cout << text.substr(0, 2000) << "\n... (truncated)" << std::endl;
            } else {
                std::cout << text << std::endl;
            }
        } else if (response.contentType.find("text/") != std::string::npos ||
                   response.contentType.find("application/json") != std::string::npos) {
            std::cout << "\n--- Content ---" << std::endl;
            if (response.body.length() > 2000) {
                std::cout << response.body.substr(0, 2000) << "\n... (truncated)" << std::endl;
            } else {
                std::cout << response.body << std::endl;
            }
        } else {
            std::cout << "\n(Binary content - not displayed)" << std::endl;
        }
        
        std::cout << "===================" << std::endl;
    } else {
        std::cerr << "Failed to load page: " << response.errorMessage << std::endl;
    }
}

void BrowserCLI::CmdBrowserBack(const std::string& args) {
    if (g_browserState.historyIndex > 0) {
        g_browserState.historyIndex--;
        std::string url = g_browserState.history[static_cast<size_t>(g_browserState.historyIndex)];
        std::cout << "Going back to: " << url << std::endl;
        CmdBrowser(url);
    } else {
        std::cout << "No previous page in history." << std::endl;
    }
}

void BrowserCLI::CmdBrowserForward(const std::string& args) {
    if (g_browserState.historyIndex + 1 < static_cast<int>(g_browserState.history.size())) {
        g_browserState.historyIndex++;
        std::string url = g_browserState.history[static_cast<size_t>(g_browserState.historyIndex)];
        std::cout << "Going forward to: " << url << std::endl;
        CmdBrowser(url);
    } else {
        std::cout << "No next page in history." << std::endl;
    }
}

void BrowserCLI::CmdBrowserReload(const std::string& args) {
    if (!g_browserState.currentURL.empty()) {
        std::cout << "Reloading: " << g_browserState.currentURL << std::endl;
        CmdBrowser(g_browserState.currentURL);
    } else {
        std::cout << "No page to reload." << std::endl;
    }
}

void BrowserCLI::CmdBrowserStop(const std::string& args) {
    std::cout << "Stopping..." << std::endl;
    g_browserState.isLoading = false;
}

void BrowserCLI::CmdDocs(const std::string& args) {
    std::cout << "Opening documentation..." << std::endl;
    
    std::string docs = R"(
=== RawrXD Documentation ===

QUICK START:
  !browser <url>     - Open URL in browser
  !docs              - Show this documentation
  !github            - Open GitHub
  !search <query>    - Search the web
  !fetch <url>       - HTTP GET request
  !post <url>        - HTTP POST request

BROWSER COMMANDS:
  !browser status    - Show browser state
  !browser history   - Show navigation history
  !back              - Go back
  !forward           - Go forward
  !reload            - Reload current page
  !stop              - Stop loading

EXAMPLES:
  !browser example.com
  !browser https://raw.githubusercontent.com
  !search RawrXD IDE
  !fetch https://api.github.com/users/github

TIP: Type !browser help for full help.

===========================
)";
    std::cout << docs << std::endl;
}

void BrowserCLI::CmdGitHub(const std::string& args) {
    CmdBrowser("https://github.com");
}

void BrowserCLI::CmdSearch(const std::string& args) {
    if (args.empty()) {
        std::cout << "Usage: !search <query>" << std::endl;
        return;
    }
    
    std::string searchURL = "https://duckduckgo.com/?q=" + BrowserUtils::URLEncode(args);
    CmdBrowser(searchURL);
}

void BrowserCLI::CmdFetch(const std::string& args) {
    if (args.empty()) {
        std::cout << "Usage: !fetch <url>" << std::endl;
        std::cout << "       !fetch https://api.example.com/data" << std::endl;
        return;
    }
    
    std::string url = args;
    if (!BrowserUtils::IsAbsoluteURL(url)) {
        url = "https://" + url;
    }
    
    std::cout << "Fetching: " << url << std::endl;
    
    if (!g_networkEngine) {
        std::cerr << "Network engine not initialized!" << std::endl;
        return;
    }
    
    HTTPResponse response = g_networkEngine->Get(url);
    
    if (response.success) {
        std::cout << "Status: " << response.statusCode << std::endl;
        std::cout << "Content-Type: " << response.contentType << std::endl;
        std::cout << "\n" << response.body << std::endl;
    } else {
        std::cerr << "Failed: " << response.errorMessage << std::endl;
    }
}

void BrowserCLI::CmdPost(const std::string& args) {
    if (args.empty()) {
        std::cout << "Usage: !post <url> [data]" << std::endl;
        std::cout << "       !post https://api.example.com/login username=admin&password=secret" << std::endl;
        return;
    }
    
    // Parse URL and data
    size_t spacePos = args.find(' ');
    std::string url = args;
    std::string data;
    
    if (spacePos != std::string::npos) {
        url = args.substr(0, spacePos);
        data = args.substr(spacePos + 1);
    }
    
    if (!BrowserUtils::IsAbsoluteURL(url)) {
        url = "https://" + url;
    }
    
    std::cout << "POST to: " << url << std::endl;
    std::cout << "Data: " << data << std::endl;
    
    if (!g_networkEngine) {
        std::cerr << "Network engine not initialized!" << std::endl;
        return;
    }
    
    HTTPResponse response = g_networkEngine->Post(url, data);
    
    if (response.success) {
        std::cout << "Status: " << response.statusCode << std::endl;
        std::cout << "\n" << response.body << std::endl;
    } else {
        std::cerr << "Failed: " << response.errorMessage << std::endl;
    }
}

std::string BrowserCLI::GetHelpText() {
    return R"(
=== RawrXD Browser Commands ===

Navigation:
  !browser <url>       - Navigate to URL
  !back                - Go back in history
  !forward             - Go forward in history
  !reload              - Reload current page
  !stop                - Stop loading

Information:
  !browser status      - Show browser state
  !browser history     - Show navigation history

Shortcuts:
  !docs                - Open documentation
  !github              - Open GitHub
  !search <query>      - Search the web

HTTP Requests:
  !fetch <url>         - HTTP GET request
  !post <url> [data]   - HTTP POST request

Examples:
  !browser example.com
  !browser https://raw.githubusercontent.com
  !search RawrXD documentation
  !fetch https://api.github.com/users/github

===============================
)";
}

void BrowserCLI::RegisterCommands() {
    // Commands are registered via HandleCommand dispatcher
    // This is called from Init()
}

} // namespace RawrXD
