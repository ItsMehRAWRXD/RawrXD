// ============================================================================
//  A narrow view of the host application for the VS Code extension API.
//
//  The extension runtime is shared by the command line and the Win32 GUI, so
//  it must not depend on the IDE's own header. The IDE provides an adapter
//  that implements this interface and forwards to its native facilities.
//
//  Keeping the surface this small is deliberate: the extension API only
//  needs a handful of routing points, and a narrow interface means the
//  command line can link the same runtime without pulling in the IDE.
// ============================================================================

#ifndef RAWRXD_EXTENSION_HOST_BRIDGE_H
#define RAWRXD_EXTENSION_HOST_BRIDGE_H

#include <windows.h>
#include <commctrl.h>

#include <string>


// A snapshot of the host settings that the extension API exposes to
// JavaScript. The adapter copies these from the IDE's own settings, so
// the runtime does not depend on the IDE's settings type.
struct ExtensionHostSettings {
    // Editor
    std::string fontName;
    int         fontSize = 0;
    int         tabSize = 0;
    bool        wordWrapEnabled = false;
    bool        useSpaces = true;
    bool        lineNumbersVisible = true;
    bool        minimapEnabled = true;
    bool        syntaxColoringEnabled = true;
    bool        ghostTextEnabled = false;
    std::string encoding;
    std::string eolStyle;

    // Files
    bool        autoSaveEnabled = false;
    int         autoSaveIntervalSec = 30;
    std::string workingDirectory;

    // Server
    bool        localServerEnabled = false;
    int         localServerPort = 0;

    // AI
    std::string aiModelPath;
    std::string aiOllamaUrl;
    double      aiTemperature = 0.0;
    double      aiTopP = 0.0;
    int         aiTopK = 0;
    int         aiMaxTokens = 0;
    int         aiContextWindow = 0;

    // Failure detection
    bool        failureDetectorEnabled = false;
    int         failureMaxRetries = 0;
};
class ExtensionHostBridge {
public:
    virtual ~ExtensionHostBridge() = default;

    // ---- Output channel ----
    virtual void addOutputTab(const std::string& name) = 0;
    virtual void appendToOutput(const std::string& text, const std::string& tabName) = 0;

    // ---- Problems ----
    virtual void addProblem(const std::string& file, int line, int col,
                            const std::string& message, int severity) = 0;

    // ---- Tree view ----
    virtual HTREEITEM addTreeItem(HTREEITEM parent, const std::string& text,
                                  const std::string& fullPath, bool isDirectory) = 0;

    // ---- Status bar ----
    virtual HWND getStatusBar() = 0;

    // ---- Debugger ----
    virtual bool isDebugActive() const = 0;
    virtual std::string getDebugCurrentFile() const = 0;

    // ---- Settings ----
    virtual ExtensionHostSettings getSettings() const = 0;
    virtual bool setSetting(const std::string& key, const std::string& value) = 0;

    // ---- Terminal ----
    //
    // The terminal send callback is invoked with the host as an opaque
    // context, so the runtime can hand it back without knowing the host
    // type.
    virtual void* terminalContext() = 0;
};


#endif // RAWRXD_EXTENSION_HOST_BRIDGE_H
