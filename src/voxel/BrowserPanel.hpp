// ============================================================================
// BrowserPanel.hpp — the browser that shows the world.
//
// This is the RawrXD browser: the same WebView2 host the IDE uses, built
// on the same hand written COM declarations in include/WebView2.h and the
// same WebView2Loader.dll. The page it loads is ours, and the bridge
// between the page and the renderer is a pair of web messages.
//
// The flow is:
//
//   the renderer draws a frame
//   the frame is read back and written as a PNG
//   the page is given the PNG and draws it into a canvas
//   the page can send commands back, such as "walk forward"
//
// The messages are JSON, because the browser side of a bridge that is
// meant to be read by an agent should be legible.
// ============================================================================

#pragma once

#include <functional>
#include <string>
#include <vector>

#include <windows.h>

#include "WebView2.h"

namespace sunshine {

// The callbacks that receive the messages from the page and that create
// the browser. They are defined in the implementation file and declared
// here so that the panel can be their friend.
struct PanelMessageHandler;
struct EnvironmentHandler;
struct ControllerHandler;

// A command the page asked for.
struct BrowserCommand {
    std::string type;         // "move", "turn", "capture", "status"
    float forward = 0.0f;
    float strafe = 0.0f;
    float rise = 0.0f;
    float turnX = 0.0f;
    float turnY = 0.0f;
    bool valid = false;
};

class BrowserPanel {
public:
    BrowserPanel() = default;
    ~BrowserPanel();

    BrowserPanel(const BrowserPanel&) = delete;
    BrowserPanel& operator=(const BrowserPanel&) = delete;

    // Create the panel inside a parent window.
    //
    // `userDataFolder` is where the browser keeps its profile. It is
    // created if it does not exist.
    bool create(HWND parent, RECT bounds, const std::wstring& userDataFolder, std::string& error);

    // Move and resize the panel.
    void setBounds(RECT bounds);

    // Load a page from a string of HTML.
    bool loadHtml(const std::string& html, std::string& error);

    // Load a page from a file on disk.
    bool loadFile(const std::string& path, std::string& error);

    // Send a message to the page. The message is JSON.
    bool postJson(const std::string& json);

    // Run a script in the page.
    bool executeScript(const std::string& script);

    // The commands the page has sent since the last call.
    std::vector<BrowserCommand> takeCommands();

    // Whether the page reported that it is ready.
    bool pageReady() const { return pageReady_; }

    // The version of the browser that is running.
    const std::string& browserVersion() const { return browserVersion_; }

    // The last error the panel recorded.
    const std::string& lastError() const { return lastError_; }

    // Whether the panel is up at all.
    bool isCreated() const { return controller_ != nullptr; }

    // Release the browser.
    void destroy();

private:
    // The callbacks the panel installs on the browser. They are friends
    // of this class so that the message handler can reach the command
    // list and the browser callbacks can reach the panel.
    friend struct PanelMessageHandler;
    friend struct EnvironmentHandler;
    friend struct ControllerHandler;

    // Whether the thread was prepared for the browser.
    bool comInitialised_ = false;

    ICoreWebView2Controller* controller_ = nullptr;
    ICoreWebView2* webview_ = nullptr;
    ICoreWebView2Environment* environment_ = nullptr;
    bool pageReady_ = false;
    std::string browserVersion_;
    std::string lastError_;
    std::vector<BrowserCommand> commands_;
};

} // namespace sunshine
