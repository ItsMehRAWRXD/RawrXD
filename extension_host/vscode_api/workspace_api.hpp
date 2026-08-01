// workspace_api.hpp — VS Code Workspace API
#pragma once
#include <string>
#include <vector>
#include <functional>
#include <filesystem>

namespace RawrXD {
namespace ExtensionHost {
namespace VSCODE {

struct WorkspaceFolder {
    std::filesystem::path path;
    std::string name;
    int index = 0;
};

struct TextDocument {
    std::filesystem::path path;
    std::string languageId;
    std::string content;
    bool isDirty = false;
    bool isUntitled = false;
};

class Workspace {
public:
    static Workspace& Get();

    // File operations
    std::vector<WorkspaceFolder> GetWorkspaceFolders() const;
    bool OpenFile(const std::filesystem::path& path);
    std::string ReadFile(const std::filesystem::path& path) const;
    bool WriteFile(const std::filesystem::path& path, const std::string& content);

    // Document tracking
    TextDocument* GetOpenDocument(const std::filesystem::path& path);
    std::vector<TextDocument> GetOpenDocuments() const;

    // File watching
    using FileChangeCallback = std::function<void(const std::filesystem::path& path, int changeType)>;
    void OnDidChangeFile(FileChangeCallback callback);
    void NotifyFileChanged(const std::filesystem::path& path, int changeType);

    // Configuration
    std::string GetConfiguration(const std::string& section) const;
    void SetConfiguration(const std::string& section, const std::string& value);

    // Workspace root
    std::filesystem::path GetRootPath() const;
    void SetRootPath(const std::filesystem::path& path);

private:
    Workspace() = default;
    std::vector<WorkspaceFolder> m_folders;
    std::vector<TextDocument> m_openDocuments;
    FileChangeCallback m_fileChangeCallback;
    std::filesystem::path m_rootPath;
};

} // namespace VSCODE
} // namespace ExtensionHost
} // namespace RawrXD
