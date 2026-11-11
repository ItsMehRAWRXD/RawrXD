// workspace_api.cpp — VS Code Workspace API Implementation
#include "workspace_api.hpp"
#include <fstream>
#include <algorithm>

namespace RawrXD {
namespace ExtensionHost {
namespace VSCODE {

Workspace& Workspace::Get() {
    static Workspace instance;
    return instance;
}

std::vector<WorkspaceFolder> Workspace::GetWorkspaceFolders() const {
    return m_folders;
}

bool Workspace::OpenFile(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) return false;

    // Check if already open
    for (auto& doc : m_openDocuments) {
        if (doc.path == path) return true;
    }

    TextDocument doc;
    doc.path = path;
    doc.languageId = path.extension().string();
    doc.content = ReadFile(path);
    doc.isDirty = false;
    doc.isUntitled = false;
    m_openDocuments.push_back(doc);
    return true;
}

std::string Workspace::ReadFile(const std::filesystem::path& path) const {
    std::ifstream file(path);
    if (!file.is_open()) return {};
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

bool Workspace::WriteFile(const std::filesystem::path& path, const std::string& content) {
    std::ofstream file(path);
    if (!file.is_open()) return false;
    file << content;
    return true;
}

TextDocument* Workspace::GetOpenDocument(const std::filesystem::path& path) {
    for (auto& doc : m_openDocuments) {
        if (doc.path == path) return &doc;
    }
    return nullptr;
}

std::vector<TextDocument> Workspace::GetOpenDocuments() const {
    return m_openDocuments;
}

void Workspace::OnDidChangeFile(FileChangeCallback callback) {
    m_fileChangeCallback = std::move(callback);
}

void Workspace::NotifyFileChanged(const std::filesystem::path& path, int changeType) {
    if (m_fileChangeCallback) {
        m_fileChangeCallback(path, changeType);
    }
}

std::string Workspace::GetConfiguration(const std::string& section) const {
    // TODO: Read from settings registry
    return {};
}

void Workspace::SetConfiguration(const std::string& section, const std::string& value) {
    // TODO: Write to settings registry
}

std::filesystem::path Workspace::GetRootPath() const {
    return m_rootPath;
}

void Workspace::SetRootPath(const std::filesystem::path& path) {
    m_rootPath = path;
    if (!m_rootPath.empty()) {
        WorkspaceFolder folder;
        folder.path = path;
        folder.name = path.filename().string();
        folder.index = 0;
        m_folders.push_back(folder);
    }
}

} // namespace VSCODE
} // namespace ExtensionHost
} // namespace RawrXD
