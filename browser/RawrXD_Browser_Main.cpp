// RawrXD_Browser_Main.cpp - Main entry point for the browser
// Example usage and test harness

#include "RawrXD_Browser.h"
#include <iostream>
#include <windows.h>

// Console output for debugging
void Log(const std::string& msg) {
    OutputDebugStringA((msg + "\n").c_str());
    std::cout << msg << std::endl;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    
    // Enable console for debugging
    AllocConsole();
    FILE* dummy;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    freopen_s(&dummy, "CONOUT$", "w", stderr);
    
    Log("RawrXD Browser - Zero Dependency Built-in Browser");
    Log("==================================================");
    Log("");
    
    using namespace RawrXD;
    
    // Create browser window
    BrowserWindow* browser = new BrowserWindow();
    
    if (!browser->Create(1200, 800, "RawrXD Browser")) {
        Log("Failed to create browser window!");
        return 1;
    }
    
    // Set up event handlers
    browser->onPageLoaded = [](const std::string& url) {
        Log("Page loaded: " + url);
    };
    
    browser->onNavigationStarted = [](const std::string& url) {
        Log("Navigating to: " + url);
    };
    
    browser->onError = [](const std::string& error) {
        Log("Error: " + error);
    };
    
    browser->onLinkClicked = [](const std::string& url) {
        Log("Link clicked: " + url);
    };
    
    // Show the window
    browser->Show();
    
    // Navigate to a test page or URL from command line
    std::string startURL = "example.com";
    if (strlen(lpCmdLine) > 0) {
        startURL = lpCmdLine;
    }
    
    // Remove quotes if present
    if (!startURL.empty() && startURL[0] == '"') {
        startURL = startURL.substr(1);
    }
    if (!startURL.empty() && startURL.back() == '"') {
        startURL.pop_back();
    }
    
    Log("Starting browser with URL: " + startURL);
    browser->Navigate(startURL);
    
    // Message loop
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    delete browser;
    
    Log("Browser closed.");
    return 0;
}

// Console main for testing
int main(int argc, char* argv[]) {
    std::string cmdLine;
    if (argc > 1) {
        cmdLine = argv[1];
    }
    
    // Convert to WinMain style
    char* cmdLinePtr = cmdLine.empty() ? nullptr : &cmdLine[0];
    return WinMain(GetModuleHandle(nullptr), nullptr, cmdLinePtr, SW_SHOW);
}
