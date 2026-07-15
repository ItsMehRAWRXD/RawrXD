#include "workspace.h"
#include <fstream>
#include <algorithm>
#include <windows.h>

namespace RawrXD {
namespace Workspace {

// FileWatcher implementation
class FileWatcher::Impl {
public:
    std::vector<HANDLE> handles_;
    std::vector<std::filesystem::path> paths_;
    std::vector<bool> recursive_;
    bool running_ = false;
    std::thread watchThread_;
    std::function<void(const FileChangeEvent&)> callback_;
    
    void watchLoop() {
        while (running_) {
            std::vector<HANDLE> waitHandles;
            for (size_t i = 0; i < handles_.size(); i++) {
                waitHandles.push_back(handles_[i]);
            }
            
            if (waitHandles.empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            
            DWORD result = WaitForMultipleObjects(
                static_cast<DWORD>(waitHandles.size()),
                waitHandles.data(),
                FALSE,
                100
            );
            
            if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + waitHandles.size()) {
                size_t idx = result - WAIT_OBJECT_0;
                // Process changes
                // TODO: ReadDirectoryChangesW
            }
        }
    }
};

FileWatcher::FileWatcher() : impl_(std::make_unique<Impl>()) {}
FileWatcher::~FileWatcher() { stopAll(); }

bool FileWatcher::startWatching(const std::filesystem::path& path, bool recursive) {
    if (!std::filesystem::exists(path)) return false;
    
    // Create file change notification handle
    HANDLE hDir = CreateFileW(
        path.wstring().c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr
    );
    
    if (hDir == INVALID_HANDLE_VALUE) return false;
    
    impl_->handles_.push_back(hDir);
    impl_->paths_.push_back(path);
    impl_->recursive_.push_back(recursive);
    
    if (!impl_->running_) {
        impl_->running_ = true;
        impl_->watchThread_ = std::thread(&Impl::watchLoop, impl_.get());
    }
    
    return true;
}

void FileWatcher::stopWatching(const std::filesystem::path& path) {
    for (size_t i = 0; i < impl_->paths_.size(); i++) {
        if (impl_->paths_[i] == path) {
            CloseHandle(impl_->handles_[i]);
            impl_->handles_.erase(impl_->handles_.begin() + i);
            impl_->paths_.erase(impl_->paths_.begin() + i);
            impl_->recursive_.erase(impl_->recursive_.begin() + i);
            break;
        }
    }
}

void FileWatcher::stopAll() {
    impl_->running_ = false;
    if (impl_->watchThread_.joinable()) {
        impl_->watchThread_.join();
    }
    
    for (auto handle : impl_->handles_) {
        CloseHandle(handle);
    }
    impl_->handles_.clear();
    impl_->paths_.clear();
    impl_->recursive_.clear();
}

// TextDocument implementation
std::vector<std::string> TextDocument::getLines() const {
    std::vector<std::string> lines;
    std::istringstream stream(content);
    std::string line;
    while (std::getline(stream, line)) {
        lines.push_back(line);
    }
    return lines;
}

std::string TextDocument::getLine(int line) const {
    auto lines = getLines();
    if (line >= 0 && line < static_cast<int>(lines.size())) {
        return lines[line];
    }
    return "";
}

int TextDocument::lineCount() const {
    return static_cast<int>(getLines().size());
}

void TextDocument::update(const std::string& newContent, int newVersion) {
    content = newContent;
    version = newVersion;
    isDirty = true;
}

// Configuration implementation
Configuration::Configuration(const std::string& section) : section_(section) {}

json Configuration::get(const std::string& key, const json& defaultValue) const {
    if (key.empty()) return data_;
    
    // Split key by dots
    std::vector<std::string> parts;
    std::istringstream iss(key);
    std::string part;
    while (std::getline(iss, part, '.')) {
        parts.push_back(part);
    }
    
    // Navigate JSON
    const json* current = &data_;
    for (const auto& p : parts) {
        if (!current->contains(p)) return defaultValue;
        current = &(*current)[p];
    }
    
    return *current;
}

template<typename T>
T Configuration::get(const std::string& key, const T& defaultValue) const {
    json val = get(key, json(defaultValue));
    try {
        return val.get<T>();
    } catch (...) {
        return defaultValue;
    }
}

void Configuration::update(const std::string& key, const json& value) {
    // Split key by dots
    std::vector<std::string> parts;
    std::istringstream iss(key);
    std::string part;
    while (std::getline(iss, part, '.')) {
        parts.push_back(part);
    }
    
    // Navigate/create JSON
    json* current = &data_;
    for (size_t i = 0; i < parts.size() - 1; i++) {
        if (!current->contains(parts[i])) {
            (*current)[parts[i]] = json::object();
        }
        current = &(*current)[parts[i]];
    }
    
    (*current)[parts.back()] = value;
    
    if (onChange) {
        onChange(key);
    }
}

bool Configuration::has(const std::string& key) const {
    return !get(key, nullptr).is_null();
}

std::vector<std::string> Configuration::keys() const {
    std::vector<std::string> result;
    for (auto& [key, value] : data_.items()) {
        result.push_back(key);
    }
    return result;
}

void Configuration::load(const std::filesystem::path& path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) return;
    
    try {
        ifs >> data_;
    } catch (...) {
        data_ = json::object();
    }
}

void Configuration::save(const std::filesystem::path& path) const {
    std::ofstream ofs(path);
    if (!ofs.is_open()) return;
    
    ofs << data_.dump(4);
}

// WorkspaceState implementation
void WorkspaceState::load(const std::filesystem::path& path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) return;
    
    json j;
    try {
        ifs >> j;
        
        if (j.contains("openFiles") && j["openFiles"].is_array()) {
            for (const auto& f : j["openFiles"]) {
                openFiles.push_back(f.get<std::string>());
            }
        }
        
        if (j.contains("activeFile")) {
            activeFile = j["activeFile"].get<std::string>();
        }
        
        if (j.contains("editorLayout") && j["editorLayout"].is_array()) {
            for (const auto& l : j["editorLayout"]) {
                editorLayout.push_back(l.get<int>());
            }
        }
        
        if (j.contains("panelState")) {
            panelState = j["panelState"];
        }
        
        if (j.contains("viewState")) {
            viewState = j["viewState"];
        }
    } catch (...) {
        // Reset to defaults
        openFiles.clear();
        activeFile.clear();
        editorLayout.clear();
        panelState = json::object();
        viewState = json::object();
    }
}

void WorkspaceState::save(const std::filesystem::path& path) const {
    json j;
    j["openFiles"] = openFiles;
    j["activeFile"] = activeFile.string();
    j["editorLayout"] = editorLayout;
    j["panelState"] = panelState;
    j["viewState"] = viewState;
    
    std::ofstream ofs(path);
    if (ofs.is_open()) {
        ofs << j.dump(4);
    }
}

// Workspace singleton
Workspace& Workspace::Instance() {
    static Workspace instance;
    return instance;
}

bool Workspace::initialize(const std::filesystem::path& workspaceFile) {
    fileWatcher_ = std::make_unique<FileWatcher>();
    fileWatcher_->onFileChanged = [this](const FileChangeEvent& event) {
        onFileSystemChanged(event);
    };
    
    if (!workspaceFile.empty() && std::filesystem::exists(workspaceFile)) {
        loadWorkspaceFile(workspaceFile);
    }
    
    // Set up state file path
    if (!folders_.empty()) {
        stateFile_ = folders_[0].uri / ".rawrxd" / "workspace.json";
        std::filesystem::create_directories(stateFile_.parent_path());
        restoreState();
    }
    
    return true;
}

void Workspace::shutdown() {
    saveState();
    if (fileWatcher_) {
        fileWatcher_->stopAll();
    }
}

void Workspace::addFolder(const std::filesystem::path& path, const std::string& name) {
    if (!std::filesystem::exists(path)) return;
    
    WorkspaceFolder folder;
    folder.uri = std::filesystem::canonical(path);
    folder.name = name.empty() ? folder.uri.filename().string() : name;
    folder.index = static_cast<int>(folders_.size());
    
    folders_.push_back(folder);
    
    // Start watching
    if (fileWatcher_) {
        fileWatcher_->startWatching(folder.uri, true);
    }
    
    // Update workspace root
    if (folders_.size() == 1) {
        workspaceRoot_ = folder.uri;
    }
}

void Workspace::removeFolder(const std::filesystem::path& path) {
    auto canonicalPath = std::filesystem::canonical(path);
    
    auto it = std::remove_if(folders_.begin(), folders_.end(),
        [&canonicalPath](const WorkspaceFolder& f) {
            return f.uri == canonicalPath;
        });
    
    if (it != folders_.end()) {
        // Stop watching
        if (fileWatcher_) {
            fileWatcher_->stopWatching(it->uri);
        }
        
        folders_.erase(it, folders_.end());
        
        // Reindex
        for (size_t i = 0; i < folders_.size(); i++) {
            folders_[i].index = static_cast<int>(i);
        }
    }
}

std::vector<WorkspaceFolder> Workspace::getFolders() const {
    return folders_;
}

std::filesystem::path Workspace::resolvePath(const std::filesystem::path& relative) const {
    if (relative.is_absolute()) return relative;
    
    // Try each workspace folder
    for (const auto& folder : folders_) {
        auto fullPath = folder.uri / relative;
        if (std::filesystem::exists(fullPath)) {
            return fullPath;
        }
    }
    
    // Return relative to first folder
    if (!folders_.empty()) {
        return folders_[0].uri / relative;
    }
    
    return relative;
}

bool Workspace::openFile(const std::filesystem::path& path) {
    auto canonicalPath = std::filesystem::weakly_canonical(path);
    std::string key = normalizePath(canonicalPath);
    
    // Check if already open
    if (documents_.find(key) != documents_.end()) {
        return true;
    }
    
    // Read file
    std::ifstream ifs(canonicalPath, std::ios::binary);
    if (!ifs.is_open()) {
        // Create untitled document
        auto doc = std::make_shared<TextDocument>();
        doc->uri = canonicalPath;
        doc->isUntitled = true;
        doc->languageId = canonicalPath.extension().string();
        if (!doc->languageId.empty() && doc->languageId[0] == '.') {
            doc->languageId = doc->languageId.substr(1);
        }
        documents_[key] = doc;
        
        if (onFileOpened) onFileOpened(canonicalPath);
        return true;
    }
    
    std::string content((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
    
    auto doc = std::make_shared<TextDocument>();
    doc->uri = canonicalPath;
    doc->content = content;
    doc->isDirty = false;
    doc->languageId = canonicalPath.extension().string();
    if (!doc->languageId.empty() && doc->languageId[0] == '.') {
        doc->languageId = doc->languageId.substr(1);
    }
    
    documents_[key] = doc;
    
    if (onFileOpened) onFileOpened(canonicalPath);
    return true;
}

bool Workspace::closeFile(const std::filesystem::path& path) {
    auto canonicalPath = std::filesystem::weakly_canonical(path);
    std::string key = normalizePath(canonicalPath);
    
    auto it = documents_.find(key);
    if (it == documents_.end()) return false;
    
    // Check if dirty
    if (it->second->isDirty) {
        // TODO: Prompt to save
    }
    
    documents_.erase(it);
    
    if (onFileClosed) onFileClosed(canonicalPath);
    return true;
}

bool Workspace::saveFile(const std::filesystem::path& path) {
    auto canonicalPath = std::filesystem::weakly_canonical(path);
    std::string key = normalizePath(canonicalPath);
    
    auto it = documents_.find(key);
    if (it == documents_.end()) return false;
    
    auto& doc = it->second;
    
    std::ofstream ofs(canonicalPath, std::ios::binary);
    if (!ofs.is_open()) return false;
    
    ofs << doc->content;
    doc->isDirty = false;
    
    if (onFileSaved) onFileSaved(canonicalPath);
    return true;
}

bool Workspace::saveAll() {
    bool allSaved = true;
    for (auto& [key, doc] : documents_) {
        if (doc->isDirty) {
            if (!saveFile(doc->uri)) {
                allSaved = false;
            }
        }
    }
    return allSaved;
}

std::shared_ptr<TextDocument> Workspace::getDocument(const std::filesystem::path& path) {
    auto canonicalPath = std::filesystem::weakly_canonical(path);
    std::string key = normalizePath(canonicalPath);
    
    auto it = documents_.find(key);
    if (it != documents_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::shared_ptr<TextDocument>> Workspace::getOpenDocuments() const {
    std::vector<std::shared_ptr<TextDocument>> result;
    for (const auto& [key, doc] : documents_) {
        result.push_back(doc);
    }
    return result;
}

std::vector<std::filesystem::path> Workspace::findFiles(const std::string& pattern,
                                                       const std::filesystem::path& root) const {
    std::vector<std::filesystem::path> results;
    
    std::filesystem::path searchRoot = root;
    if (searchRoot.empty() && !folders_.empty()) {
        searchRoot = folders_[0].uri;
    }
    
    if (!std::filesystem::exists(searchRoot)) return results;
    
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(searchRoot)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                // Simple pattern matching (supports * wildcard)
                if (pattern == "*" || pattern == "*.*" ||
                    (pattern.find('*') != std::string::npos &&
                     filename.find(pattern.substr(1)) != std::string::npos) ||
                    filename == pattern) {
                    results.push_back(entry.path());
                }
            }
        }
    } catch (...) {
        // Ignore permission errors
    }
    
    return results;
}

std::vector<std::filesystem::path> Workspace::findText(const std::string& query,
                                                       const std::filesystem::path& root) const {
    std::vector<std::filesystem::path> results;
    
    auto files = findFiles("*", root);
    
    for (const auto& file : files) {
        try {
            std::ifstream ifs(file);
            if (!ifs.is_open()) continue;
            
            std::string content((std::istreambuf_iterator<char>(ifs)),
                               std::istreambuf_iterator<char>());
            
            if (content.find(query) != std::string::npos) {
                results.push_back(file);
            }
        } catch (...) {
            // Ignore errors
        }
    }
    
    return results;
}

Configuration& Workspace::getConfiguration(const std::string& section) {
    if (configurations_.find(section) == configurations_.end()) {
        configurations_[section] = std::make_unique<Configuration>(section);
        
        // Load from file
        if (!folders_.empty()) {
            auto configPath = folders_[0].uri / ".rawrxd" / "settings.json";
            configurations_[section]->load(configPath);
        }
    }
    return *configurations_[section];
}

void Workspace::updateConfiguration(const std::string& section, const std::string& key, const json& value) {
    auto& config = getConfiguration(section);
    config.update(key, value);
    
    // Save to file
    if (!folders_.empty()) {
        auto configPath = folders_[0].uri / ".rawrxd" / "settings.json";
        config.save(configPath);
    }
    
    if (onConfigurationChanged) {
        onConfigurationChanged();
    }
}

void Workspace::saveState() {
    if (stateFile_.empty()) return;
    
    state_.openFiles.clear();
    for (const auto& [key, doc] : documents_) {
        state_.openFiles.push_back(doc->uri);
    }
    
    // TODO: Set active file, editor layout, etc.
    
    state_.save(stateFile_);
}

void Workspace::restoreState() {
    if (stateFile_.empty() || !std::filesystem::exists(stateFile_)) return;
    
    state_.load(stateFile_);
    
    // Reopen files
    for (const auto& file : state_.openFiles) {
        openFile(file);
    }
}

bool Workspace::isGitRepository(const std::filesystem::path& path) const {
    auto checkPath = path;
    if (std::filesystem::is_regular_file(checkPath)) {
        checkPath = checkPath.parent_path();
    }
    
    while (!checkPath.empty()) {
        auto gitDir = checkPath / ".git";
        if (std::filesystem::exists(gitDir)) {
            return true;
        }
        auto parent = checkPath.parent_path();
        if (parent == checkPath) break;
        checkPath = parent;
    }
    
    return false;
}

std::filesystem::path Workspace::getGitRoot(const std::filesystem::path& path) const {
    auto checkPath = path;
    if (std::filesystem::is_regular_file(checkPath)) {
        checkPath = checkPath.parent_path();
    }
    
    while (!checkPath.empty()) {
        auto gitDir = checkPath / ".git";
        if (std::filesystem::exists(gitDir)) {
            return checkPath;
        }
        auto parent = checkPath.parent_path();
        if (parent == checkPath) break;
        checkPath = parent;
    }
    
    return "";
}

std::string Workspace::getGitBranch(const std::filesystem::path& path) const {
    auto gitRoot = getGitRoot(path);
    if (gitRoot.empty()) return "";
    
    auto headFile = gitRoot / ".git" / "HEAD";
    std::ifstream ifs(headFile);
    if (!ifs.is_open()) return "";
    
    std::string line;
    std::getline(ifs, line);
    
    // Parse: ref: refs/heads/main
    if (line.find("ref: refs/heads/") == 0) {
        return line.substr(16);
    }
    
    // Detached HEAD
    return line.substr(0, 7); // Short SHA
}

void Workspace::loadWorkspaceFile(const std::filesystem::path& path) {
    workspaceFile_ = path;
    
    std::ifstream ifs(path);
    if (!ifs.is_open()) return;
    
    json j;
    try {
        ifs >> j;
    } catch (...) {
        return;
    }
    
    // Load folders
    if (j.contains("folders") && j["folders"].is_array()) {
        for (const auto& folder : j["folders"]) {
            if (folder.contains("path")) {
                std::string folderPath = folder["path"].get<std::string>();
                std::string name = folder.value("name", "");
                addFolder(folderPath, name);
            }
        }
    }
    
    // Load settings
    if (j.contains("settings")) {
        auto& config = getConfiguration();
        for (auto& [key, value] : j["settings"].items()) {
            config.update(key, value);
        }
    }
}

void Workspace::saveWorkspaceFile() const {
    if (workspaceFile_.empty()) return;
    
    json j;
    j["folders"] = json::array();
    for (const auto& folder : folders_) {
        json f;
        f["path"] = folder.uri.string();
        if (!folder.name.empty()) {
            f["name"] = folder.name;
        }
        j["folders"].push_back(f);
    }
    
    // Save settings
    auto& config = const_cast<Workspace*>(this)->getConfiguration();
    j["settings"] = json::object();
    for (const auto& key : config.keys()) {
        j["settings"][key] = config.get(key);
    }
    
    std::ofstream ofs(workspaceFile_);
    if (ofs.is_open()) {
        ofs << j.dump(4);
    }
}

void Workspace::onFileSystemChanged(const FileChangeEvent& event) {
    // Update document if open
    std::string key = normalizePath(event.path);
    auto it = documents_.find(key);
    if (it != documents_.end()) {
        if (event.type == FileChangeEvent::Type::Deleted) {
            it->second->isDirty = true; // Mark as modified externally
        } else if (event.type == FileChangeEvent::Type::Changed) {
            // Reload if not dirty
            if (!it->second->isDirty) {
                openFile(event.path); // Re-read from disk
            }
        }
    }
    
    if (onFileChanged) {
        onFileChanged(event);
    }
}

std::string Workspace::normalizePath(const std::filesystem::path& path) const {
    return std::filesystem::weakly_canonical(path).string();
}

// WorkspaceFile implementation
void WorkspaceFile::load(const std::filesystem::path& path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) return;
    
    json j;
    try {
        ifs >> j;
    } catch (...) {
        return;
    }
    
    folders.clear();
    if (j.contains("folders") && j["folders"].is_array()) {
        for (const auto& f : j["folders"]) {
            WorkspaceFolder folder;
            folder.uri = f.value("path", "");
            folder.name = f.value("name", "");
            folders.push_back(folder);
        }
    }
    
    if (j.contains("settings")) settings = j["settings"];
    if (j.contains("extensions")) extensions = j["extensions"];
    if (j.contains("launch")) launch = j["launch"];
    if (j.contains("tasks")) tasks = j["tasks"];
}

void WorkspaceFile::save(const std::filesystem::path& path) const {
    json j;
    
    j["folders"] = json::array();
    for (const auto& folder : folders) {
        json f;
        f["path"] = folder.uri.string();
        if (!folder.name.empty()) {
            f["name"] = folder.name;
        }
        j["folders"].push_back(f);
    }
    
    if (!settings.empty()) j["settings"] = settings;
    if (!extensions.empty()) j["extensions"] = extensions;
    if (!launch.empty()) j["launch"] = launch;
    if (!tasks.empty()) j["tasks"] = tasks;
    
    std::ofstream ofs(path);
    if (ofs.is_open()) {
        ofs << j.dump(4);
    }
}

} // namespace Workspace
} // namespace RawrXD