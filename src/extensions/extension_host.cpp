// ============================================================================
// extension_host.cpp — RawrXD Extension Host Implementation
// Implements extension_api_v1.h
// ============================================================================

#include "extension_api_v1.h"
#include <windows.h>
#include <shlwapi.h>
#include <fstream>
#include <sstream>
#include <mutex>

#pragma comment(lib, "shlwapi.lib")

namespace RawrXD {
namespace Extensions {

// Forward declarations of service implementations
class EditorImpl;
class LanguageServerImpl;
class TerminalImpl;
class FileSystemImpl;
class StatusBarImpl;
class ConfigurationImpl;
class OutputChannelImpl;

// Extension Host Implementation
class ExtensionHostImpl : public IExtensionHost {
private:
    std::unordered_map<std::string, std::shared_ptr<IExtension>> extensions_;
    std::unordered_map<std::string, CommandCallback> commands_;
    std::vector<EventCallback> documentOpenedCallbacks_;
    std::vector<EventCallback> documentClosedCallbacks_;
    std::vector<EventCallback> documentSavedCallbacks_;
    std::vector<EventCallback> cursorMovedCallbacks_;
    std::vector<EventCallback> selectionChangedCallbacks_;
    
    mutable std::mutex mutex_;
    
    // Services
    IEditor* editor_ = nullptr;
    ILanguageServer* languageServer_ = nullptr;
    ITerminal* terminal_ = nullptr;
    IFileSystem* fileSystem_ = nullptr;
    IStatusBar* statusBar_ = nullptr;
    IConfiguration* configuration_ = nullptr;

public:
    ExtensionHostImpl() = default;
    ~ExtensionHostImpl() override = default;
    
    void initialize(IEditor* editor, ILanguageServer* langServer, 
                   ITerminal* terminal, IFileSystem* fs,
                   IStatusBar* status, IConfiguration* config) {
        editor_ = editor;
        languageServer_ = langServer;
        terminal_ = terminal;
        fileSystem_ = fs;
        statusBar_ = status;
        configuration_ = config;
    }
    
    // Core services
    IEditor* getEditor() override { return editor_; }
    ILanguageServer* getLanguageServer() override { return languageServer_; }
    ITerminal* getTerminal() override { return terminal_; }
    IFileSystem* getFileSystem() override { return fileSystem_; }
    IStatusBar* getStatusBar() override { return statusBar_; }
    IConfiguration* getConfiguration() override { return configuration_; }
    
    IOutputChannel* createOutputChannel(const std::string& name) override {
        return new OutputChannelImpl(name);
    }
    
    // Extension management
    bool registerExtension(std::shared_ptr<IExtension> extension) override {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (!extension) return false;
        
        const auto& manifest = extension->getManifest();
        if (extensions_.find(manifest.id) != extensions_.end()) {
            return false;
        }
        
        extensions_[manifest.id] = extension;
        
        if (extension->initialize()) {
            extension->activate();
            return true;
        } else {
            extensions_.erase(manifest.id);
            return false;
        }
    }
    
    bool unregisterExtension(const std::string& extensionId) override {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = extensions_.find(extensionId);
        if (it == extensions_.end()) return false;
        
        it->second->deactivate();
        it->second->shutdown();
        extensions_.erase(it);
        
        return true;
    }
    
    IExtension* getExtension(const std::string& extensionId) override {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = extensions_.find(extensionId);
        return (it != extensions_.end()) ? it->second.get() : nullptr;
    }
    
    std::vector<std::shared_ptr<IExtension>> getAllExtensions() override {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::vector<std::shared_ptr<IExtension>> result;
        for (const auto& [id, ext] : extensions_) {
            result.push_back(ext);
        }
        
        return result;
    }
    
    // Commands
    bool registerCommand(const std::string& commandId, CommandCallback callback) override {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (commands_.find(commandId) != commands_.end()) {
            return false;
        }
        
        commands_[commandId] = callback;
        return true;
    }
    
    bool unregisterCommand(const std::string& commandId) override {
        std::lock_guard<std::mutex> lock(mutex_);
        return commands_.erase(commandId) > 0;
    }
    
    void executeCommand(const std::string& commandId, const std::vector<std::string>& args) override {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = commands_.find(commandId);
        if (it != commands_.end()) {
            it->second(args);
        }
    }
    
    // Events
    void onDocumentOpened(EventCallback callback) override {
        std::lock_guard<std::mutex> lock(mutex_);
        documentOpenedCallbacks_.push_back(callback);
    }
    
    void onDocumentClosed(EventCallback callback) override {
        std::lock_guard<std::mutex> lock(mutex_);
        documentClosedCallbacks_.push_back(callback);
    }
    
    void onDocumentSaved(EventCallback callback) override {
        std::lock_guard<std::mutex> lock(mutex_);
        documentSavedCallbacks_.push_back(callback);
    }
    
    void onCursorMoved(EventCallback callback) override {
        std::lock_guard<std::mutex> lock(mutex_);
        cursorMovedCallbacks_.push_back(callback);
    }
    
    void onSelectionChanged(EventCallback callback) override {
        std::lock_guard<std::mutex> lock(mutex_);
        selectionChangedCallbacks_.push_back(callback);
    }
    
    // Event triggers
    void triggerDocumentOpened() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& cb : documentOpenedCallbacks_) cb();
    }
    
    void triggerDocumentClosed() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& cb : documentClosedCallbacks_) cb();
    }
    
    void triggerDocumentSaved() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& cb : documentSavedCallbacks_) cb();
    }
    
    void triggerCursorMoved() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& cb : cursorMovedCallbacks_) cb();
    }
    
    void triggerSelectionChanged() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& cb : selectionChangedCallbacks_) cb();
    }
};

// Global instance
static std::unique_ptr<ExtensionHostImpl> g_extensionHost;

IExtensionHost* GetExtensionHost() {
    if (!g_extensionHost) {
        g_extensionHost = std::make_unique<ExtensionHostImpl>();
    }
    return g_extensionHost.get();
}

void InitializeExtensionHost(IEditor* editor, ILanguageServer* langServer,
                             ITerminal* terminal, IFileSystem* fs,
                             IStatusBar* status, IConfiguration* config) {
    auto* host = GetExtensionHost();
    if (host) {
        static_cast<ExtensionHostImpl*>(host)->initialize(editor, langServer, terminal, fs, status, config);
    }
}

void ShutdownExtensionHost() {
    if (g_extensionHost) {
        auto extensions = g_extensionHost->getAllExtensions();
        for (auto& ext : extensions) {
            ext->deactivate();
            ext->shutdown();
        }
        g_extensionHost.reset();
    }
}

// ============================================================================
// Service Implementations (stubs - to be wired to actual IDE services)
// ============================================================================

class EditorImpl : public IEditor {
public:
    std::string getActiveDocument() const override { return ""; }
    std::string getDocumentContent(const std::string& path) const override { return ""; }
    void setDocumentContent(const std::string& path, const std::string& content) override {}
    void insertText(const std::string& text) override {}
    void replaceSelection(const std::string& text) override {}
    int getCursorLine() const override { return 0; }
    int getCursorColumn() const override { return 0; }
    void setCursorPosition(int line, int column) override {}
    std::string getSelectedText() const override { return ""; }
    void selectLine(int line) override {}
    void selectAll() override {}
    int getFirstVisibleLine() const override { return 0; }
    int getLastVisibleLine() const override { return 0; }
    void scrollToLine(int line) override {}
};

class LanguageServerImpl : public ILanguageServer {
public:
    std::vector<CompletionItem> requestCompletions(const std::string& filePath, int line, int column) override {
        return {};
    }
    HoverInfo requestHover(const std::string& filePath, int line, int column) override {
        return {"", ""};
    }
    std::vector<Location> goToDefinition(const std::string& filePath, int line, int column) override {
        return {};
    }
    std::vector<Location> findReferences(const std::string& symbol, const std::string& filePath, int line, int column) override {
        return {};
    }
    std::vector<Diagnostic> getDiagnostics(const std::string& filePath) override {
        return {};
    }
};

class TerminalImpl : public ITerminal {
public:
    void executeCommand(const std::string& command) override {}
    std::string executeAndGetOutput(const std::string& command) override { return ""; }
    void sendText(const std::string& text) override {}
    void clear() override {}
    std::string getWorkingDirectory() const override { return ""; }
    void setWorkingDirectory(const std::string& path) override {}
};

class FileSystemImpl : public IFileSystem {
public:
    bool fileExists(const std::string& path) const override {
        DWORD attrs = GetFileAttributesA(path.c_str());
        return attrs != INVALID_FILE_ATTRIBUTES;
    }
    
    bool directoryExists(const std::string& path) const override {
        DWORD attrs = GetFileAttributesA(path.c_str());
        return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
    }
    
    std::string readFile(const std::string& path) const override {
        std::ifstream file(path);
        if (!file) return "";
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }
    
    void writeFile(const std::string& path, const std::string& content) override {
        std::ofstream file(path);
        if (file) file << content;
    }
    
    void deleteFile(const std::string& path) override {
        DeleteFileA(path.c_str());
    }
    
    void createDirectory(const std::string& path) override {
        CreateDirectoryA(path.c_str(), nullptr);
    }
    
    std::vector<std::string> listDirectory(const std::string& path) const override {
        std::vector<std::string> result;
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA((path + "\\*").c_str(), &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                    result.push_back(findData.cFileName);
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
        
        return result;
    }
    
    std::string getAbsolutePath(const std::string& relativePath) const override {
        char fullPath[MAX_PATH];
        GetFullPathNameA(relativePath.c_str(), MAX_PATH, fullPath, nullptr);
        return fullPath;
    }
    
    std::string joinPaths(const std::string& path1, const std::string& path2) const override {
        return path1 + "\\" + path2;
    }
};

class StatusBarImpl : public IStatusBar {
public:
    void showMessage(const std::string& message, int timeout) override {
        // TODO: Implement status bar
    }
    
    void showWarning(const std::string& message, int timeout) override {
        // TODO: Implement status bar
    }
    
    void showError(const std::string& message, int timeout) override {
        // TODO: Implement status bar
    }
    
    void setProgress(double percentage) override {}
    void clearProgress() override {}
};

class ConfigurationImpl : public IConfiguration {
private:
    std::unordered_map<std::string, std::string> values_;
    
public:
    template<typename T>
    T getValue(const std::string& key, const T& defaultValue) const override {
        auto it = values_.find(key);
        if (it != values_.end()) {
            // Simple string conversion - real impl would use JSON
            return static_cast<T>(it->second);
        }
        return defaultValue;
    }
    
    void setValue(const std::string& key, const std::string& value) override {
        values_[key] = value;
    }
    
    bool hasKey(const std::string& key) const override {
        return values_.find(key) != values_.end();
    }
    
    void removeKey(const std::string& key) override {
        values_.erase(key);
    }
};

class OutputChannelImpl : public IOutputChannel {
private:
    std::string name_;
    
public:
    OutputChannelImpl(const std::string& name) : name_(name) {}
    
    void append(const std::string& message) override {
        // TODO: Implement output channel
    }
    
    void appendLine(const std::string& message) override {
        append(message + "\n");
    }
    
    void clear() override {}
    void show() override {}
    void hide() override {}
};

} // namespace Extensions
} // namespace RawrXD

// Window API implementation
class Window {
public:
    void ShowInformationMessage(const std::string& message) {
        MessageBoxA(nullptr, message.c_str(), "RawrXD", MB_OK | MB_ICONINFORMATION);
    }
    
    void ShowErrorMessage(const std::string& message) {
        MessageBoxA(nullptr, message.c_str(), "RawrXD", MB_OK | MB_ICONERROR);
    }
};

// Workspace API implementation
class Workspace {
public:
    std::string GetWorkspaceFolder() {
        char path[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, path);
        return std::string(path);
    }
    
    std::vector<std::string> GetTextDocuments() {
        // Return list of open documents
        return {};
    }
};

// Languages API implementation
class Languages {
public:
    void RegisterCompletionProvider(const std::string& language, 
                                    std::function<std::vector<std::string>(const std::string&)> provider) {
        providers_[language] = provider;
    }
    
private:
    std::map<std::string, std::function<std::vector<std::string>(const std::string&)>> providers_;
};

// Debug API implementation
class Debug {
public:
    void RegisterDebugConfigurationProvider(const std::string& type, 
                                           std::function<bool(const std::string&)> provider) {
        providers_[type] = provider;
    }
    
private:
    std::map<std::string, std::function<bool(const std::string&)>> providers_;
};

// Terminal API implementation
class Terminal {
public:
    void CreateTerminal(const std::string& name, const std::string& shellPath) {
        // Create terminal instance
    }
};

// ExtensionHost implementation
ExtensionHost& ExtensionHost::Instance() {
    static ExtensionHost instance;
    return instance;
}

bool ExtensionHost::Initialize() {
    // Initialize QuickJS runtime
    quickJSRuntime_ = JS_NewRuntime();
    if (!quickJSRuntime_) return false;
    
    quickJSContext_ = JS_NewContext(quickJSRuntime_);
    if (!quickJSContext_) {
        JS_FreeRuntime(quickJSRuntime_);
        return false;
    }
    
    // Initialize API implementations
    commands_ = std::make_unique<Commands>();
    window_ = std::make_unique<Window>();
    workspace_ = std::make_unique<Workspace>();
    languages_ = std::make_unique<Languages>();
    debug_ = std::make_unique<Debug>();
    terminal_ = std::make_unique<Terminal>();
    
    // Load all installed extensions
    char extensionsPath[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, extensionsPath);
    PathAppendA(extensionsPath, "\\RawrXD\\extensions");
    
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA((std::string(extensionsPath) + "\\*").c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                    std::string extPath = std::string(extensionsPath) + "\\" + findData.cFileName;
                    LoadExtension(extPath);
                }
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
    
    return true;
}

bool ExtensionHost::Shutdown() {
    // Deactivate all extensions
    std::lock_guard<std::mutex> lock(extensionsMutex_);
    for (auto& [id, ext] : extensions_) {
        ext->Deactivate();
    }
    extensions_.clear();
    
    // Cleanup QuickJS
    if (quickJSContext_) {
        JS_FreeContext(quickJSContext_);
        quickJSContext_ = nullptr;
    }
    if (quickJSRuntime_) {
        JS_FreeRuntime(quickJSRuntime_);
        quickJSRuntime_ = nullptr;
    }
    
    return true;
}

bool ExtensionHost::LoadExtension(const std::string& path) {
    // Read package.json
    std::string packagePath = path + "\\package.json";
    std::ifstream file(packagePath);
    if (!file.is_open()) return false;
    
    std::string jsonStr((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();
    
    // Parse manifest
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(jsonStr, root)) return false;
    
    auto ext = std::make_unique<Extension>();
    ext->manifest.name = root.get("name", "").asString();
    ext->manifest.version = root.get("version", "").asString();
    ext->manifest.publisher = root.get("publisher", "").asString();
    ext->manifest.description = root.get("description", "").asString();
    ext->manifest.main = root.get("main", "extension.js").asString();
    
    const Json::Value& activationEvents = root["activationEvents"];
    for (const auto& event : activationEvents) {
        ext->manifest.activationEvents.push_back(event.asString());
    }
    
    // Create context
    ext->context = std::make_unique<ExtensionContext>();
    ext->context->extensionPath = path;
    ext->context->commands = commands_.get();
    ext->context->window = window_.get();
    ext->context->workspace = workspace_.get();
    
    std::string extId = ext->manifest.publisher + "." + ext->manifest.name;
    
    std::lock_guard<std::mutex> lock(extensionsMutex_);
    extensions_[extId] = std::move(ext);
    
    return true;
}

bool ExtensionHost::UnloadExtension(const std::string& extensionId) {
    std::lock_guard<std::mutex> lock(extensionsMutex_);
    auto it = extensions_.find(extensionId);
    if (it == extensions_.end()) return false;
    
    it->second->Deactivate();
    extensions_.erase(it);
    return true;
}

bool ExtensionHost::EnableExtension(const std::string& extensionId) {
    std::lock_guard<std::mutex> lock(extensionsMutex_);
    auto it = extensions_.find(extensionId);
    if (it == extensions_.end()) return false;
    
    it->second->manifest.enabled = true;
    return true;
}

bool ExtensionHost::DisableExtension(const std::string& extensionId) {
    std::lock_guard<std::mutex> lock(extensionsMutex_);
    auto it = extensions_.find(extensionId);
    if (it == extensions_.end()) return false;
    
    it->second->manifest.enabled = false;
    it->second->Deactivate();
    return true;
}

void ExtensionHost::ActivateByEvent(const std::string& event) {
    std::lock_guard<std::mutex> lock(extensionsMutex_);
    for (auto& [id, ext] : extensions_) {
        if (!ext->manifest.enabled || ext->isActive) continue;
        
        for (const auto& activationEvent : ext->manifest.activationEvents) {
            if (activationEvent == event || activationEvent == "*") {
                ext->Activate();
                break;
            }
        }
    }
}

void ExtensionHost::ActivateByCommand(const std::string& command) {
    ActivateByEvent("onCommand:" + command);
}

void ExtensionHost::ActivateByLanguage(const std::string& language) {
    ActivateByEvent("onLanguage:" + language);
}

bool ExtensionHost::InstallFromVSIX(const std::string& vsixPath) {
    // Extract VSIX (zip file) to extensions folder
    char extensionsPath[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, extensionsPath);
    PathAppendA(extensionsPath, "\\RawrXD\\extensions");
    
    // Create directory if needed
    CreateDirectoryA(extensionsPath, nullptr);
    
    // Extract using Windows Shell
    // This is simplified - real implementation would use proper zip extraction
    std::string extractCmd = "powershell -command \"Expand-Archive -Path '\"" + vsixPath + "'\" -DestinationPath '\"" + extensionsPath + "'\"\"";
    system(extractCmd.c_str());
    
    return true;
}

bool Extension::Activate() {
    if (isActive) return true;
    
    // Load and execute extension script
    std::string scriptPath = context->extensionPath + "\\" + manifest.main;
    
    // TODO: Execute in QuickJS context with API bindings
    
    isActive = true;
    return true;
}

bool Extension::Deactivate() {
    if (!isActive) return true;
    
    // Cleanup
    isActive = false;
    return true;
}

} // namespace Extensions
} // namespace RawrXD
