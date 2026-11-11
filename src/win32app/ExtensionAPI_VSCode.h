// ExtensionAPI_VSCode.h — VS Code Extension API Compatibility (Batch 5 X02)
// Minimal but functional API surface for real VS Code extensions
#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <map>

namespace RawrXD::Extensions::VSCodeAPI {

class WorkspaceFolder;
class TextDocument;
class Uri;
class QuickPickItem;
class Progress;
class DiagnosticCollection;
class Hover;
class CompletionItem;

class Uri {
public:
    static Uri File(const std::string& path);
    static Uri Parse(const std::string& value);

    std::string GetScheme() const { return m_scheme; }
    std::string GetPath() const { return m_path; }
    std::string ToString() const;

private:
    Uri(const std::string& scheme, const std::string& path);
    std::string m_scheme;
    std::string m_path;
};

class TextDocument {
public:
    std::string uri;
    std::string getText() const;
};

class Window {
public:
    void showInformationMessage(const std::string& message);
    void showErrorMessage(const std::string& message);
};

class Workspace {
public:
    std::vector<std::shared_ptr<TextDocument>> textDocuments;
};

class Commands {
public:
    void registerCommand(const std::string& command, std::function<void()> callback);
    void executeCommand(const std::string& command);
};

struct ExtensionContext {
    std::string extensionPath;
    void subscribe(std::function<void()> disposeFunc);
};

extern Window window;
extern Workspace workspace;
extern Commands commands;

} // namespace RawrXD::Extensions::VSCodeAPI
