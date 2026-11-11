// window_api.cpp — VS Code Window API Implementation
#include "window_api.hpp"
#include <iostream>

namespace RawrXD {
namespace ExtensionHost {
namespace VSCODE {

Window& Window::Get() {
    static Window instance;
    return instance;
}

void Window::ShowInformationMessage(const std::string& message) {
    MessageBoxA(nullptr, message.c_str(), "RawrXD", MB_OK | MB_ICONINFORMATION);
}

void Window::ShowWarningMessage(const std::string& message) {
    MessageBoxA(nullptr, message.c_str(), "RawrXD - Warning", MB_OK | MB_ICONWARNING);
}

void Window::ShowErrorMessage(const std::string& message) {
    MessageBoxA(nullptr, message.c_str(), "RawrXD - Error", MB_OK | MB_ICONERROR);
}

void Window::SetStatusBarMessage(const std::string& message) {
    // TODO: Update status bar in Win32 IDE
    std::cout << "[Status] " << message << std::endl;
}

void Window::SetStatusBarMessageWithTimeout(const std::string& message, int timeoutMs) {
    SetStatusBarMessage(message);
    // TODO: Clear after timeout
}

void Window::WithProgress(const std::string& title, ProgressCallback callback) {
    // TODO: Show progress dialog
    if (callback) callback(0);
}

void Window::ShowTextDocument(const std::string& path) {
    // TODO: Open file in editor
}

void Window::SetEditorFocus() {
    // TODO: Focus the editor window
}

std::string Window::GetClipboard() const {
    // TODO: Read from Win32 clipboard
    return {};
}

void Window::SetClipboard(const std::string& text) {
    // TODO: Write to Win32 clipboard
}

} // namespace VSCODE
} // namespace ExtensionHost
} // namespace RawrXD
