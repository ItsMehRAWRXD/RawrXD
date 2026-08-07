// window_api.hpp — VS Code Window API
#pragma once
#include <string>
#include <functional>

namespace RawrXD {
namespace ExtensionHost {
namespace VSCODE {

class Window {
public:
    static Window& Get();

    // Message dialogs
    void ShowInformationMessage(const std::string& message);
    void ShowWarningMessage(const std::string& message);
    void ShowErrorMessage(const std::string& message);

    // Status bar
    void SetStatusBarMessage(const std::string& message);
    void SetStatusBarMessageWithTimeout(const std::string& message, int timeoutMs);

    // Progress
    using ProgressCallback = std::function<void(int progress)>;
    void WithProgress(const std::string& title, ProgressCallback callback);

    // Active editor focus
    void ShowTextDocument(const std::string& path);
    void SetEditorFocus();

    // Clipboard
    std::string GetClipboard() const;
    void SetClipboard(const std::string& text);

    // Events
    using WindowCallback = std::function<void()>;
    void OnDidChangeWindowFocus(WindowCallback callback) { m_onFocus = callback; }

private:
    Window() = default;
    WindowCallback m_onFocus;
};

} // namespace VSCODE
} // namespace ExtensionHost
} // namespace RawrXD
