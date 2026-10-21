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
        host_->addOutputTab(name);
    }

    void appendToOutput(const std::string& text, const std::string& tabName) override {
        if (!host_) return;
        host_->appendToOutput(text, tabName);
    }

    // ---- Problems ----
    void addProblem(const std::string& file, int line, int col,
                    const std::string& message, int severity) override {
        if (!host_) return;
        int ideSeverity = kSeverityInfo;
        if (severity == 0) ideSeverity = kSeverityError;
        else if (severity == 1) ideSeverity = kSeverityWarning;
        host_->addProblem(file, line, col, message, ideSeverity);
    }

    // ---- Tree view ----
    HTREEITEM addTreeItem(HTREEITEM parent, const std::string& text,
                          const std::string& fullPath, bool isDirectory) override {
        if (!host_) return nullptr;
        return host_->addTreeItem(parent, text, fullPath, isDirectory);
    }

    // ---- Status bar ----
    HWND getStatusBar() override {
        if (!host_) return nullptr;
        return host_->getStatusBar();
    }

    // ---- Debugger ----
    bool isDebugActive() const override {
        if (!host_) return false;
        return host_->isDebugActive();
    }

    std::string getDebugCurrentFile() const override {
        if (!host_) return std::string();
        return host_->getDebugCurrentFile();
    }

    // ---- Settings ----
    ExtensionHostSettings getSettings() const override {
        ExtensionHostSettings settings;
        if (!host_) return settings;

        // The IDE owns the settings; the runtime only reads the subset the
        // VS Code API exposes.
        const IDESettings& ide = host_->getSettingsMut();
        settings.fontName = ide.fontName;
        settings.fontSize = ide.fontSize;
        settings.tabSize = ide.tabSize;
        settings.wordWrapEnabled = ide.wordWrapEnabled;
        settings.useSpaces = ide.useSpaces;
        settings.lineNumbersVisible = ide.lineNumbersVisible;
        settings.minimapEnabled = ide.minimapEnabled;
        settings.syntaxColoringEnabled = ide.syntaxColoringEnabled;
        settings.ghostTextEnabled = ide.ghostTextEnabled;
        settings.encoding = ide.encoding;
        settings.eolStyle = ide.eolStyle;
        settings.autoSaveEnabled = ide.autoSaveEnabled;
        settings.autoSaveIntervalSec = ide.autoSaveIntervalSec;
        settings.workingDirectory = ide.workingDirectory;
        settings.localServerEnabled = ide.localServerEnabled;
        settings.localServerPort = ide.localServerPort;
        settings.aiModelPath = ide.aiModelPath;
        settings.aiOllamaUrl = ide.aiOllamaUrl;
        settings.aiTemperature = ide.aiTemperature;
        settings.aiTopP = ide.aiTopP;
        settings.aiTopK = ide.aiTopK;
        settings.aiMaxTokens = ide.aiMaxTokens;
        settings.aiContextWindow = ide.aiContextWindow;
        settings.failureDetectorEnabled = ide.failureDetectorEnabled;
        settings.failureMaxRetries = ide.failureMaxRetries;
        return settings;
    }

    bool setSetting(const std::string& key, const std::string& value) override {
        if (!host_) return false;
        IDESettings& ide = host_->getSettingsMut();

        if (key == "editor.fontFamily" || key == "fontName") {
            ide.fontName = value;
        } else if (key == "editor.fontSize" || key == "fontSize") {
            ide.fontSize = std::atoi(value.c_str());
        } else if (key == "editor.tabSize" || key == "tabSize") {
            ide.tabSize = std::atoi(value.c_str());
        } else if (key == "editor.wordWrap" || key == "wordWrapEnabled") {
            ide.wordWrapEnabled = (value == "true" || value == "on" || value == "1");
        } else if (key == "files.encoding" || key == "encoding") {
            ide.encoding = value;
        } else if (key == "files.eol" || key == "eolStyle") {
            ide.eolStyle = value;
        } else if (key == "ai.temperature" || key == "aiTemperature") {
            ide.aiTemperature = std::atof(value.c_str());
        } else if (key == "ai.topP" || key == "aiTopP") {
            ide.aiTopP = std::atof(value.c_str());
        } else if (key == "ai.maxTokens" || key == "aiMaxTokens") {
            ide.aiMaxTokens = std::atoi(value.c_str());
        } else if (key == "ai.contextWindow" || key == "aiContextWindow") {
            ide.aiContextWindow = std::atoi(value.c_str());
        } else if (key == "ai.modelPath" || key == "aiModelPath") {
            ide.aiModelPath = value;
        } else if (key == "ai.ollamaUrl" || key == "aiOllamaUrl") {
            ide.aiOllamaUrl = value;
        } else {
            return false;
        }
        return true;
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
