// ============================================================================
//  A headless host bridge.
//
//  The extension runtime is shared by the IDE and the command line. The IDE
//  provides the Win32 bridge; this one is for every other consumer, and it
//  satisfies the interface without routing anything to a window.
//
//  The settings surface reports the defaults and refuses writes, which is
//  the honest answer for a host that has no configuration store.
// ============================================================================

#include "extension_host_bridge.h"

class HeadlessExtensionHostBridge final : public ExtensionHostBridge {
public:
    // ---- Output channel ----
    void addOutputTab(const std::string& name) override {
        lastTab_ = name;
    }

    void appendToOutput(const std::string& text, const std::string& tabName) override {
        lastOutput_ += text;
        lastTab_ = tabName;
    }

    // ---- Problems ----
    void addProblem(const std::string& file, int line, int col,
                    const std::string& message, int severity) override {
        lastProblem_ = file + ":" + std::to_string(line) + ":" +
                       std::to_string(col) + " " + message;
        lastSeverity_ = severity;
    }

    // ---- Tree view ----
    HTREEITEM addTreeItem(HTREEITEM parent, const std::string& text,
                          const std::string& fullPath, bool isDirectory) override {
        (void)parent;
        (void)text;
        (void)fullPath;
        (void)isDirectory;
        return nullptr;
    }

    // ---- Status bar ----
    HWND getStatusBar() override { return nullptr; }

    // ---- Debugger ----
    bool isDebugActive() const override { return false; }
    std::string getDebugCurrentFile() const override { return std::string(); }

    // ---- Settings ----
    ExtensionHostSettings getSettings() const override {
        return ExtensionHostSettings();
    }

    bool setSetting(const std::string& key, const std::string& value) override {
        (void)key;
        (void)value;
        return false;
    }

    // ---- Terminal ----
    void* terminalContext() override { return nullptr; }

    // ---- What the host observed ----
    const std::string& lastOutput() const { return lastOutput_; }
    const std::string& lastProblem() const { return lastProblem_; }
    int lastSeverity() const { return lastSeverity_; }

private:
    std::string lastTab_;
    std::string lastOutput_;
    std::string lastProblem_;
    int lastSeverity_ = 0;
};

ExtensionHostBridge* CreateHeadlessExtensionHostBridge() {
    return new HeadlessExtensionHostBridge();
}

void DestroyExtensionHostBridge(ExtensionHostBridge* bridge) {
    delete bridge;
}


