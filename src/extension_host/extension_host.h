#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Extensions {

using json = nlohmann::json;

// Extension manifest (package.json equivalent)
struct ExtensionManifest {
    std::string name;
    std::string version;
    std::string publisher;
    std::string description;
    std::vector<std::string> keywords;
    std::string main;           // Entry point script
    std::vector<std::string> activationEvents;
    json contributes;           // Commands, menus, views, etc.
    json engines;               // VS Code version compatibility
    
    bool isValid() const {
        return !name.empty() && !version.empty() && !main.empty();
    }
};

// Extension lifecycle states
enum class ExtensionState {
    Uninstalled,
    Installed,
    Activating,
    Active,
    Deactivating,
    Inactive,
    Error
};

// Extension context (passed to activate function)
struct ExtensionContext {
    std::string extensionPath;
    std::string storagePath;
    std::string logPath;
    json globalState;
    json workspaceState;
    
    std::vector<std::function<void()>> subscriptions;
    
    void subscribe(std::function<void()> dispose) {
        subscriptions.push_back(dispose);
    }
};

// Extension instance
class Extension {
public:
    ExtensionManifest manifest;
    ExtensionState state = ExtensionState::Installed;
    std::string id;
    std::string path;
    std::unique_ptr<ExtensionContext> context;
    
    // QuickJS runtime references
    void* jsContext = nullptr;
    void* activateFunc = nullptr;
    void* deactivateFunc = nullptr;
    
    Extension(const ExtensionManifest& manifest, const std::string& path);
    ~Extension();
    
    bool activate();
    bool deactivate();
    bool isActive() const { return state == ExtensionState::Active; }
};

// Command registration
struct Command {
    std::string id;
    std::string title;
    std::string category;
    std::function<void(const json& args)> handler;
    std::string extensionId;
};

// Tree view item
struct TreeItem {
    std::string id;
    std::string label;
    std::string description;
    std::string tooltip;
    std::string iconPath;
    std::string contextValue;
    bool collapsibleState = false;
    std::vector<TreeItem> children;
    json command;
};

// Tree data provider interface
class TreeDataProvider {
public:
    virtual ~TreeDataProvider() = default;
    virtual TreeItem getTreeItem(const std::string& element) = 0;
    virtual std::vector<std::string> getChildren(const std::string& element) = 0;
    std::function<void()> onDidChangeTreeData;
};

// Webview panel
class WebviewPanel {
public:
    std::string viewType;
    std::string title;
    int column = 1; // Active = 1, Beside = 2, etc.
    json options;
    
    std::function<void()> onDidDispose;
    std::function<void()> onDidChangeViewState;
    
    void postMessage(const json& message);
    void setHtml(const std::string& html);
    void reveal(int column = 1, bool preserveFocus = false);
};

// Extension Host - Main API surface
class ExtensionHost {
public:
    static ExtensionHost& Instance();
    
    // Lifecycle
    bool initialize();
    void shutdown();
    
    // Extension management
    bool installExtension(const std::string& vsixPath);
    bool uninstallExtension(const std::string& extensionId);
    bool enableExtension(const std::string& extensionId);
    bool disableExtension(const std::string& extensionId);
    
    std::vector<std::shared_ptr<Extension>> getExtensions();
    std::shared_ptr<Extension> getExtension(const std::string& id);
    
    // Activation
    void activateByEvent(const std::string& event);
    void activateByCommand(const std::string& commandId);
    void activateByLanguage(const std::string& language);
    void activateByFile(const std::string& filePath);
    
    // Commands API
    void registerCommand(const std::string& id, std::function<void(const json&)> handler, const std::string& extensionId);
    void executeCommand(const std::string& id, const json& args = json::object());
    std::vector<Command> getCommands();
    
    // Tree views
    void registerTreeDataProvider(const std::string& viewId, std::shared_ptr<TreeDataProvider> provider);
    TreeItem getTreeItem(const std::string& viewId, const std::string& element);
    
    // Webviews
    std::shared_ptr<WebviewPanel> createWebviewPanel(const std::string& viewType, const std::string& title, 
                                                      int column, const json& options);
    
    // VS Code API compatibility
    json getVSCodeAPI(const std::string& extensionId);
    
    // Event emitters
    std::function<void(const std::string& extensionId, ExtensionState state)> onExtensionStateChanged;
    std::function<void(const std::string& message)> onLogMessage;

private:
    ExtensionHost() = default;
    ~ExtensionHost() = default;
    
    std::unordered_map<std::string, std::shared_ptr<Extension>> extensions_;
    std::unordered_map<std::string, Command> commands_;
    std::unordered_map<std::string, std::shared_ptr<TreeDataProvider>> treeProviders_;
    std::vector<std::shared_ptr<WebviewPanel>> webviewPanels_;
    
    void* quickJSRuntime_ = nullptr;
    std::string extensionsPath_;
    
    bool loadExtension(const std::string& path);
    ExtensionManifest parseManifest(const std::string& manifestPath);
    bool activateExtension(std::shared_ptr<Extension> ext);
    bool deactivateExtension(std::shared_ptr<Extension> ext);
    
    // QuickJS integration
    bool initializeQuickJS();
    void shutdownQuickJS();
    bool executeScript(const std::string& script, void* context);
    json callJSFunction(void* func, const json& args);
};

// Global extension API (exposed to extensions)
namespace API {
    // Commands
    void registerCommand(const std::string& id, std::function<void(const json&)> handler);
    void executeCommand(const std::string& id, const json& args);
    
    // Window
    void showInformationMessage(const std::string& message);
    void showWarningMessage(const std::string& message);
    void showErrorMessage(const std::string& message);
    
    // Workspace
    std::string getWorkspaceFolder();
    std::vector<std::string> getWorkspaceFolders();
    std::string getConfiguration(const std::string& section);
    void updateConfiguration(const std::string& section, const json& value);
    
    // Editor
    std::string getActiveEditor();
    void openTextDocument(const std::string& path);
    void showTextDocument(const std::string& path, int column = 1);
    
    // Language
    void registerCompletionItemProvider(const std::string& language, void* provider);
    void registerDefinitionProvider(const std::string& language, void* provider);
    void registerHoverProvider(const std::string& language, void* provider);
    
    // Debug
    void startDebugging(const std::string& name, const json& config);
    void stopDebugging();
    void registerDebugConfigurationProvider(const std::string& type, void* provider);
    
    // Tasks
    void registerTaskProvider(const std::string& type, void* provider);
    void executeTask(const json& task);
    
    // SCM
    void registerSCMProvider(const std::string& id, void* provider);
    
    // Tree views
    void registerTreeDataProvider(const std::string& viewId, std::shared_ptr<TreeDataProvider> provider);
    void registerWebviewPanelSerializer(const std::string& viewType, void* serializer);
}

} // namespace Extensions
} // namespace RawrXD