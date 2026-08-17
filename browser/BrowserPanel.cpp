// BrowserPanel.cpp - Browser Panel Implementation for RawrXD IDE

#include "BrowserPanel.hpp"
#include "../ide/HotkeySystem.hpp"
#include "../ide/DockingLayout.hpp"
#include <iostream>

namespace RawrXD {

void BrowserPanel::Init() {
    if (s_initialized) return;
    
    std::cout << "[BrowserPanel] Initializing..." << std::endl;
    
    // Browser will be created on first show
    s_initialized = true;
    
    // Register hotkeys
    RegisterHotkeys();
    
    // Add to docking layout
    DockingLayout::Add(PANEL_ID, DockingLayout::Right);
    
    std::cout << "[BrowserPanel] Initialized" << std::endl;
}

void BrowserPanel::Shutdown() {
    if (!s_initialized) return;
    
    std::cout << "[BrowserPanel] Shutting down..." << std::endl;
    
    if (s_browser) {
        delete s_browser;
        s_browser = nullptr;
    }
    
    s_initialized = false;
    s_visible = false;
}

void BrowserPanel::CreateBrowser() {
    if (s_browser) return;
    
    s_browser = new BrowserWindow();
    
    if (!s_browser->Create(1024, 768, "RawrXD Browser")) {
        std::cerr << "[BrowserPanel] Failed to create browser window" << std::endl;
        delete s_browser;
        s_browser = nullptr;
        return;
    }
    
    // Set up event handlers
    s_browser->onPageLoaded = [](const std::string& url) {
        std::cout << "[Browser] Page loaded: " << url << std::endl;
    };
    
    s_browser->onNavigationStarted = [](const std::string& url) {
        std::cout << "[Browser] Navigating to: " << url << std::endl;
    };
    
    s_browser->onError = [](const std::string& error) {
        std::cerr << "[Browser] Error: " << error << std::endl;
    };
    
    s_browser->onLinkClicked = [](const std::string& url) {
        std::cout << "[Browser] Link clicked: " << url << std::endl;
    };
}

void BrowserPanel::Toggle() {
    if (s_visible) {
        Hide();
    } else {
        Show();
    }
}

void BrowserPanel::Show() {
    if (!s_initialized) {
        Init();
    }
    
    if (!s_browser) {
        CreateBrowser();
    }
    
    if (s_browser) {
        s_browser->Show();
        s_visible = true;
        
        // Navigate to default page if not already loaded
        if (s_browser->GetCurrentURL().empty()) {
            Navigate("rawrxd://welcome");
        }
    }
}

void BrowserPanel::Hide() {
    if (s_browser) {
        s_browser->Hide();
    }
    s_visible = false;
}

bool BrowserPanel::IsVisible() {
    return s_visible;
}

void BrowserPanel::Navigate(const std::string& url) {
    if (!s_browser) {
        Show();
    }
    
    if (s_browser) {
        // Handle special rawrxd:// URLs
        if (url.find("rawrxd://") == 0) {
            std::string resource = url.substr(9);
            if (resource == "welcome") {
                // Load welcome HTML
                std::string welcomeHTML = R"(
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Browser - Welcome</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 40px; background: #1e1e1e; color: #d4d4d4; }
        h1 { color: #0078d4; }
        .feature { margin: 20px 0; padding: 15px; background: #252526; border-left: 4px solid #0078d4; }
        a { color: #4fc1ff; }
        code { background: #3c3c3c; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>🚀 RawrXD Built-in Browser</h1>
    <p>Welcome to the zero-dependency browser integrated into RawrXD IDE!</p>
    
    <div class="feature">
        <h3>Features</h3>
        <ul>
            <li>Zero external dependencies - pure Win32</li>
            <li>HTTP/HTTPS support via WinHTTP</li>
            <li>Custom HTML/CSS rendering</li>
            <li>Integrated with IDE docking system</li>
        </ul>
    </div>
    
    <div class="feature">
        <h3>Quick Commands</h3>
        <ul>
            <li><code>Ctrl+Shift+B</code> - Toggle browser</li>
            <li><code>F5</code> - Refresh page</li>
            <li><code>Escape</code> - Stop loading</li>
        </ul>
    </div>
    
    <div class="feature">
        <h3>Try These URLs</h3>
        <ul>
            <li><a href="https://example.com">example.com</a></li>
            <li><a href="https://raw.githubusercontent.com">GitHub Raw</a></li>
            <li><a href="rawrxd://docs">Documentation</a></li>
        </ul>
    </div>
</body>
</html>
)";
                s_browser->LoadHTML(welcomeHTML, "rawrxd://welcome");
                return;
            } else if (resource == "docs") {
                std::string docsHTML = R"(
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Documentation</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 40px; background: #1e1e1e; color: #d4d4d4; }
        h1 { color: #0078d4; }
        h2 { color: #4fc1ff; border-bottom: 1px solid #3c3c3c; padding-bottom: 8px; }
        code { background: #3c3c3c; padding: 2px 6px; border-radius: 3px; }
        pre { background: #252526; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>📚 RawrXD Documentation</h1>
    
    <h2>Getting Started</h2>
    <p>RawrXD is a high-performance AI-powered IDE with zero dependencies.</p>
    
    <h2>Commands</h2>
    <pre><code>!browser [url]     - Open browser with URL
!docs              - Open documentation
!github            - Open GitHub
!search [query]    - Search the web</code></pre>
    
    <h2>Keyboard Shortcuts</h2>
    <ul>
        <li><code>Ctrl+Shift+B</code> - Toggle browser panel</li>
        <li><code>F5</code> - Refresh</li>
        <li><code>Alt+Left</code> - Back</li>
        <li><code>Alt+Right</code> - Forward</li>
    </ul>
</body>
</html>
)";
                s_browser->LoadHTML(docsHTML, "rawrxd://docs");
                return;
            }
        }
        
        s_browser->Navigate(url);
    }
}

void BrowserPanel::NavigateBack() {
    if (s_browser) {
        s_browser->NavigateBack();
    }
}

void BrowserPanel::NavigateForward() {
    if (s_browser) {
        s_browser->NavigateForward();
    }
}

void BrowserPanel::Reload() {
    if (s_browser) {
        s_browser->Reload();
    }
}

void BrowserPanel::Stop() {
    if (s_browser) {
        s_browser->Stop();
    }
}

std::string BrowserPanel::GetCurrentURL() {
    if (s_browser) {
        return s_browser->GetCurrentURL();
    }
    return "";
}

std::string BrowserPanel::GetPageTitle() {
    if (s_browser) {
        return s_browser->GetPageTitle();
    }
    return "";
}

bool BrowserPanel::IsLoading() {
    if (s_browser) {
        // TODO: Add IsLoading to BrowserWindow
        return false;
    }
    return false;
}

HWND BrowserPanel::GetHWND() {
    if (s_browser) {
        return s_browser->GetHWND();
    }
    return nullptr;
}

void BrowserPanel::RegisterHotkeys() {
    // Register browser hotkeys
    HotkeySystem::Register("Ctrl+Shift+B", []() { Toggle(); });
    HotkeySystem::Register("Ctrl+Shift+D", []() { BrowserCommands::OpenDocumentation(); });
    HotkeySystem::Register("Ctrl+Shift+G", []() { BrowserCommands::OpenGitHub(); });
}

// ============================================================================
// Browser Commands
// ============================================================================

void BrowserCommands::OpenURL(const std::string& url) {
    BrowserPanel::Navigate(url);
}

void BrowserCommands::OpenDocumentation() {
    BrowserPanel::Navigate("rawrxd://docs");
}

void BrowserCommands::OpenGitHub() {
    BrowserPanel::Navigate("https://github.com");
}

void BrowserCommands::OpenSettings() {
    BrowserPanel::Navigate("rawrxd://settings");
}

void BrowserCommands::Search(const std::string& query) {
    std::string searchURL = "https://duckduckgo.com/?q=" + BrowserUtils::URLEncode(query);
    BrowserPanel::Navigate(searchURL);
}

} // namespace RawrXD
