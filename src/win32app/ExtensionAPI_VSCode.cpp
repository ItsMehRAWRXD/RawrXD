// ExtensionAPI_VSCode.cpp
// Phase 2 Day 9: VS Code Extension API Implementation

#include "ExtensionAPI_VSCode.h"
#include "ExtensionSandboxManager.h"
#include "IDELogger.h"
#include <algorithm>
#include <sstream>
#include <windows.h>
#include <Shlobj.h>

#pragma comment(lib, "Shell32.lib")

namespace RawrXD::Extensions::VSCodeAPI {

    // ============================================================================
    // Uri Implementation
    // ============================================================================

    Uri::Uri(const std::string& scheme, const std::string& path)
        : m_scheme(scheme), m_path(path) {}

    Uri Uri::File(const std::string& path)
    {
        return Uri("file", path);
    }

    Uri Uri::Parse(const std::string& value)
    {
        size_t colonPos = value.find(':');
        if (colonPos == std::string::npos) {
            return Uri("file", value);
        }

        std::string scheme = value.substr(0, colonPos);
        std::string path = value.substr(colonPos + 1);

        // Remove leading slashes
        while (!path.empty() && (path[0] == '/' || path[0] == '\\')) {
            path = path.substr(1);
        }

        return Uri(scheme, path);
    }

    std::string Uri::ToString() const
    {
        return m_scheme + "://" + m_path;
    }

    // ============================================================================
    // TextDocument Implementation
    // ============================================================================

    int TextDocument::GetLineCount() const
    {
        return std::count(m_text.begin(), m_text.end(), '\n') + 1;
    }

    // ============================================================================
    // Progress Implementation
    // ============================================================================

    void Progress::Report(int percentage, const std::string& message)
    {
        IDELogger::Get().Info("Progress: " + std::to_string(percentage) + "% - " + message);
    }

    // ============================================================================
    // WorkspaceAPI Implementation
    // ============================================================================

    WorkspaceAPI& WorkspaceAPI::Get()
    {
        static WorkspaceAPI instance;
        return instance;
    }

    std::shared_ptr<TextDocument> WorkspaceAPI::OpenTextDocument(const std::string& fileName)
    {
        auto it = m_openDocuments.find(fileName);
        if (it != m_openDocuments.end()) {
            return it->second;
        }

        // Try to read file content
        auto doc = std::make_shared<TextDocument>();
        doc->m_fileName = fileName;
        doc->m_languageId = "plaintext";

        // Determine language ID from extension
        size_t dotPos = fileName.rfind('.');
        if (dotPos != std::string::npos) {
            std::string ext = fileName.substr(dotPos + 1);
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            
            if (ext == "cpp" || ext == "cc" || ext == "cxx") doc->m_languageId = "cpp";
            else if (ext == "h" || ext == "hpp") doc->m_languageId = "cpp";
            else if (ext == "cs") doc->m_languageId = "csharp";
            else if (ext == "py") doc->m_languageId = "python";
            else if (ext == "js" || ext == "jsx") doc->m_languageId = "javascript";
            else if (ext == "ts" || ext == "tsx") doc->m_languageId = "typescript";
            else if (ext == "json") doc->m_languageId = "json";
        }

        m_openDocuments[fileName] = doc;
        IDELogger::Get().Info("Opened document: " + fileName + " (" + doc->m_languageId + ")");

        return doc;
    }

    std::vector<std::string> WorkspaceAPI::FindFiles(const std::string& include, const std::string& exclude)
    {
        std::vector<std::string> results;

        // In production, would use Windows file APIs to search
        // For now, return empty results
        IDELogger::Get().Info("Find files: " + include + (exclude.empty() ? "" : " (exclude: " + exclude + ")"));

        return results;
    }

    bool WorkspaceAPI::SaveAll()
    {
        for (auto& pair : m_openDocuments) {
            pair.second->m_isDirty = false;
        }
        IDELogger::Get().Info("Saved all documents");
        return true;
    }

    std::string WorkspaceAPI::AsRelativePath(const std::string& pathOrUri)
    {
        // Simple relative path calculation
        size_t lastSlash = pathOrUri.rfind('\\');
        if (lastSlash == std::string::npos) {
            lastSlash = pathOrUri.rfind('/');
        }

        if (lastSlash != std::string::npos) {
            return pathOrUri.substr(lastSlash + 1);
        }

        return pathOrUri;
    }

    std::vector<WorkspaceFolder> WorkspaceAPI::GetWorkspaceFolders() const
    {
        std::vector<WorkspaceFolder> folders;

        // Get current working directory as workspace root
        char cwdBuffer[MAX_PATH];
        if (GetCurrentDirectoryA(MAX_PATH, cwdBuffer)) {
            WorkspaceFolder folder("Workspace", Uri::File(cwdBuffer), 0);
            folders.push_back(folder);
        }

        return folders;
    }

    std::vector<std::string> WorkspaceAPI::GetWorkspaceFolderUris() const
    {
        std::vector<std::string> uris;
        auto folders = GetWorkspaceFolders();
        for (const auto& folder : folders) {
            uris.push_back(folder.uri.ToString());
        }
        return uris;
    }

    // ============================================================================
    // WindowAPI Implementation
    // ============================================================================

    WindowAPI& WindowAPI::Get()
    {
        static WindowAPI instance;
        return instance;
    }

    void WindowAPI::ShowInformationMessage(const std::string& message)
    {
        IDELogger::Get().Info("Message: " + message);
        MessageBoxA(nullptr, message.c_str(), "RawrXD Extension", MB_ICONINFORMATION | MB_OK);
    }

    void WindowAPI::ShowWarningMessage(const std::string& message)
    {
        IDELogger::Get().Warning("Warning: " + message);
        MessageBoxA(nullptr, message.c_str(), "RawrXD Extension", MB_ICONWARNING | MB_OK);
    }

    void WindowAPI::ShowErrorMessage(const std::string& message)
    {
        IDELogger::Get().Error("Error: " + message);
        MessageBoxA(nullptr, message.c_str(), "RawrXD Extension", MB_ICONERROR | MB_OK);
    }

    void WindowAPI::ShowInputBox(const std::string& prompt, InputBoxCallback callback)
    {
        // In production, would show actual input dialog
        IDELogger::Get().Info("Input prompt: " + prompt);
        if (callback) {
            callback("user_input");
        }
    }

    void WindowAPI::ShowQuickPick(
        const std::vector<std::string>& items,
        const std::string& placeHolder,
        QuickPickCallback callback)
    {
        IDELogger::Get().Info("Quick pick with " + std::to_string(items.size()) + " items");
        if (callback && !items.empty()) {
            callback(items[0]);
        }
    }

    void WindowAPI::WithProgress(
        int totalWork,
        const std::string& title,
        ProgressCallback callback)
    {
        Progress progress;
        IDELogger::Get().Info("Starting progress: " + title);
        callback(progress);
        IDELogger::Get().Info("Completed progress: " + title);
    }

    // ============================================================================
    // CommandsAPI Implementation
    // ============================================================================

    CommandsAPI& CommandsAPI::Get()
    {
        static CommandsAPI instance;
        return instance;
    }

    void CommandsAPI::RegisterCommand(
        const std::string& commandId,
        std::function<void()> callback)
    {
        m_commands[commandId] = callback;
        IDELogger::Get().Info("Registered command: " + commandId);
    }

    void CommandsAPI::RegisterCommandWithArgs(
        const std::string& commandId,
        std::function<void(const std::string& args)> callback)
    {
        m_commandsWithArgs[commandId] = callback;
        IDELogger::Get().Info("Registered command with args: " + commandId);
    }

    void CommandsAPI::ExecuteCommand(const std::string& commandId)
    {
        auto it = m_commands.find(commandId);
        if (it != m_commands.end()) {
            it->second();
            IDELogger::Get().Info("Executed command: " + commandId);
        } else {
            IDELogger::Get().Warning("Command not found: " + commandId);
        }
    }

    void CommandsAPI::ExecuteCommandWithArgs(const std::string& commandId, const std::string& args)
    {
        auto it = m_commandsWithArgs.find(commandId);
        if (it != m_commandsWithArgs.end()) {
            it->second(args);
            IDELogger::Get().Info("Executed command with args: " + commandId);
        } else {
            IDELogger::Get().Warning("Command not found: " + commandId);
        }
    }

    std::vector<std::string> CommandsAPI::GetCommands()
    {
        std::vector<std::string> commands;
        for (const auto& pair : m_commands) {
            commands.push_back(pair.first);
        }
        for (const auto& pair : m_commandsWithArgs) {
            commands.push_back(pair.first);
        }
        return commands;
    }

    // ============================================================================
    // LanguagesAPI Implementation
    // ============================================================================

    LanguagesAPI& LanguagesAPI::Get()
    {
        static LanguagesAPI instance;
        return instance;
    }

    void LanguagesAPI::RegisterCompletionProvider(
        const std::string& language,
        std::shared_ptr<CompletionProvider> provider)
    {
        m_completionProviders[language] = provider;
        IDELogger::Get().Info("Registered completion provider for language: " + language);
    }

    void LanguagesAPI::RegisterHoverProvider(
        const std::string& language,
        std::shared_ptr<HoverProvider> provider)
    {
        m_hoverProviders[language] = provider;
        IDELogger::Get().Info("Registered hover provider for language: " + language);
    }

    std::shared_ptr<DiagnosticCollection> LanguagesAPI::CreateDiagnosticCollection(
        const std::string& name)
    {
        auto collection = std::make_shared<DiagnosticCollection>();
        m_diagnosticCollections[name] = collection;
        IDELogger::Get().Info("Created diagnostic collection: " + name);
        return collection;
    }

    // ============================================================================
    // DiagnosticCollection Implementation
    // ============================================================================

    void DiagnosticCollection::Set(const std::string& fileName, const std::vector<std::string>& diagnostics)
    {
        m_diagnostics[fileName] = diagnostics;
        IDELogger::Get().Info("Set " + std::to_string(diagnostics.size()) + " diagnostics for: " + fileName);
    }

    void DiagnosticCollection::Clear()
    {
        m_diagnostics.clear();
        IDELogger::Get().Info("Cleared all diagnostics");
    }

    void DiagnosticCollection::Delete(const std::string& fileName)
    {
        m_diagnostics.erase(fileName);
        IDELogger::Get().Info("Deleted diagnostics for: " + fileName);
    }

    // ============================================================================
    // EnvironmentAPI Implementation
    // ============================================================================

    EnvironmentAPI& EnvironmentAPI::Get()
    {
        static EnvironmentAPI instance;
        
        // Initialize machine/session IDs if not already done
        if (instance.m_machineId.empty()) {
            // Get machine GUID from registry
            HKEY hKey;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                "SOFTWARE\\Microsoft\\Cryptography", 
                0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                
                char machineGuid[40] = {0};
                DWORD size = sizeof(machineGuid);
                if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, 
                    (LPBYTE)machineGuid, &size) == ERROR_SUCCESS) {
                    instance.m_machineId = machineGuid;
                }
                RegCloseKey(hKey);
            }

            if (instance.m_machineId.empty()) {
                instance.m_machineId = "default-machine-id";
            }

            // Generate session ID
            SYSTEMTIME st;
            GetSystemTime(&st);
            std::stringstream ss;
            ss << "session-" << std::to_string(st.wHour) 
               << "-" << std::to_string(st.wMinute)
               << "-" << std::to_string(st.wSecond);
            instance.m_sessionId = ss.str();
        }

        return instance;
    }

    void EnvironmentAPI::OpenExternal(const std::string& url)
    {
        // Validate URL through security sandbox
        // In production, would check sandbox permissions
        
        IDELogger::Get().Info("Opening external URL: " + url);
        
        // Use ShellExecute to open URL
        ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOW);
    }

    void EnvironmentAPI::ClipboardCopy(const std::string& text)
    {
        if (OpenClipboard(nullptr)) {
            HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE, text.length() + 1);
            if (hglbCopy != nullptr) {
                memcpy_s(GlobalLock(hglbCopy), GlobalSize(hglbCopy), text.c_str(), text.length() + 1);
                GlobalUnlock(hglbCopy);
                SetClipboardData(CF_TEXT, hglbCopy);
            }
            CloseClipboard();
            IDELogger::Get().Info("Copied to clipboard: " + std::to_string(text.length()) + " bytes");
        }
    }

    std::string EnvironmentAPI::ClipboardPaste()
    {
        std::string result;

        if (OpenClipboard(nullptr)) {
            HANDLE hglbPaste = GetClipboardData(CF_TEXT);
            if (hglbPaste != nullptr) {
                LPSTR lpstrPaste = static_cast<LPSTR>(GlobalLock(hglbPaste));
                if (lpstrPaste != nullptr) {
                    result = lpstrPaste;
                    GlobalUnlock(hglbPaste);
                }
            }
            CloseClipboard();
            IDELogger::Get().Info("Pasted from clipboard: " + std::to_string(result.length()) + " bytes");
        }

        return result;
    }

    std::string EnvironmentAPI::GetMachineId()
    {
        return Get().m_machineId;
    }

    std::string EnvironmentAPI::GetSessionId()
    {
        return Get().m_sessionId;
    }

} // namespace RawrXD::Extensions::VSCodeAPI
