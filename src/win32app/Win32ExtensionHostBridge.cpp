// ============================================================================
//  The Win32 IDE's implementation of the extension host bridge.
//
//  The extension runtime is shared with the command line, so it must not
//  depend on the IDE's own header. Instead the IDE provides this adapter,
//  which forwards the handful of routing points that the VS Code API needs
//  to the IDE's native facilities.
//
//  This file is the only place that knows about both sides.
// ============================================================================

#include "extension_host_bridge.h"

#include "Win32IDE.h"

#include <string>

namespace {

// The severity values the IDE's problem list uses.
constexpr int kSeverityError = 0;
constexpr int kSeverityWarning = 1;
constexpr int kSeverityInfo = 2;

} // namespace

namespace RawrXD {
namespace Extensions {

class Win32ExtensionHostBridge final : public ExtensionHostBridge {
public:
    explicit Win32ExtensionHostBridge(Win32IDE* host) : host_(host) {}

    // ---- Output channel ----
    void addOutputTab(const std::string& name) override {
        if (!host_) return;
        host_->extAddOutputTab(name);
    }

    void appendToOutput(const std::string& text, const std::string& tabName) override {
        if (!host_) return;
        host_->extAppendToOutput(text, tabName);
    }

    // ---- Problems ----
    void addProblem(const std::string& file, int line, int col,
                    const std::string& message, int severity) override {
        if (!host_) return;
        int ideSeverity = kSeverityInfo;
        if (severity == 0) ideSeverity = kSeverityError;
        else if (severity == 1) ideSeverity = kSeverityWarning;
        host_->extAddProblem(file, line, col, message, ideSeverity);
    }

    // ---- Tree view ----
    HTREEITEM addTreeItem(HTREEITEM parent, const std::string& text,
                          const std::string& fullPath, bool isDirectory) override {
        if (!host_) return nullptr;
        return host_->extAddTreeItem(parent, text, fullPath, isDirectory);
    }

    // ---- Status bar ----
    HWND getStatusBar() override {
        if (!host_) return nullptr;
        return host_->extGetStatusBar();
    }

    // ---- Debugger ----
    bool isDebugActive() const override {
        if (!host_) return false;
        return host_->extIsDebugging();
    }

    std::string getDebugCurrentFile() const override {
        if (!host_) return std::string();
        return host_->extGetCurrentFilePath();
    }

    // ---- Settings ----
    //
    // The IDE does not yet have a configuration store that the extension
    // API can read or write, so the snapshot carries the defaults and
    // writes are refused. Reporting the refusal is honest: the extension is
    // told the key is unknown rather than being told a write succeeded and
    // then losing the value.
    ExtensionHostSettings getSettings() const override {
        return ExtensionHostSettings();
    }

    bool setSetting(const std::string& key, const std::string& value) override {
        (void)key;
        (void)value;
        return false;
    }

    // ---- Terminal ----
    void* terminalContext() override {
        // The terminal callback receives the host as an opaque context.
        return static_cast<void*>(host_);
    }

private:
    Win32IDE* host_ = nullptr;
};

ExtensionHostBridge* CreateWin32ExtensionHostBridge(Win32IDE* host) {
    return new Win32ExtensionHostBridge(host);
}

void DestroyWin32ExtensionHostBridge(ExtensionHostBridge* bridge) {
    delete bridge;
}

} // namespace Extensions
} // namespace RawrXD
