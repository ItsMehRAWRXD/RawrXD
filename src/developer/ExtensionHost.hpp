// Phase Y.2/5: Extension Host
// RawrXD Extension Host - VS Code-compatible extension system

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>
#include <variant>

namespace RawrXD {
namespace Developer {

// Extension manifest (VS Code-compatible)
struct ExtensionManifest {
    std::string name;
    std::string displayName;
    std::string version;
    std::string publisher;
    std::string description;
    std::string license;
    std::string homepage;
    std::string repository;
    std::string bugs;
    
    // Engine compatibility
    std::string engines_rawrxd;
    std::vector<std::string> engines_vscode;
    
    // Categories
    std::vector<std::string> categories;
    std::vector<std::string> keywords;
    
    // Activation
    std::vector<std::string> activationEvents;
    
    // Contributions
    struct Contributions {
        std::vector<std::unordered_map<std::string, std::string>> commands;
        std::vector<std::unordered_map<std::string, std::string>> menus;
        std::vector<std::unordered_map<std::string, std::string>> keybindings;
        std::vector<std::unordered_map<std::string, std::string>> configuration;
        std::vector<std::unordered_map<std::string, std::string>> views;
        std::vector<std::unordered_map<std::string, std::string>> themes;
        std::vector<std::unordered_map<std::string, std::string>> grammars;
        std::vector<std::unordered_map<std::string, std::string>> debuggers;
        std::vector<std::unordered_map<std::string, std::string>> taskDefinitions;
    } contributions;
    
    // Scripts
    std::string main;
    std::unordered_map<std::string, std::string> scripts;
    
    // Dependencies
    std::vector<std::string> extensionDependencies;
    std::vector<std::string> extensionPack;
    std::unordered_map<std::string, std::string> extensionKind;
};

// Extension state
enum class ExtensionState {
    INSTALLED,
    ENABLED,
    ACTIVATED,
    DISABLED,
    ERROR
};

// Extension info
struct ExtensionInfo {
    std::string id;
    ExtensionManifest manifest;
    ExtensionState state;
    std::string path;
    std::chrono::system_clock::time_point installed_at;
    std::chrono::system_clock::time_point activated_at;
    std::string error_message;
    bool is_builtin;
    bool is_under_development;
};

// Extension API - VS Code-compatible
class IExtensionAPI {
public:
    virtual ~IExtensionAPI() = default;
    
    // Version
    virtual std::string GetVersion() const = 0;
    
    // Commands
    virtual std::string RegisterCommand(const std::string& command,
                                          std::function<void(const std::vector<std::string>& args)> handler) = 0;
    virtual bool UnregisterCommand(const std::string& command) = 0;
    virtual void ExecuteCommand(const std::string& command,
                                   const std::vector<std::string>& args = {}) = 0;
    
    // Workspace
    virtual std::string GetWorkspacePath() const = 0;
    virtual std::vector<std::string> GetOpenFiles() const = 0;
    virtual std::optional<std::string> GetActiveFile() const = 0;
    virtual std::string GetFileContent(const std::string& path) = 0;
    virtual bool SetFileContent(const std::string& path, const std::string& content) = 0;
    
    // Window
    virtual void ShowInformationMessage(const std::string& message) = 0;
    virtual void ShowWarningMessage(const std::string& message) = 0;
    virtual void ShowErrorMessage(const std::string& message) = 0;
    virtual std::optional<std::string> ShowInputBox(const std::string& prompt,
                                                     const std::string& default_value = "") = 0;
    virtual std::optional<std::string> ShowQuickPick(const std::vector<std::string>& items,
                                                      const std::string& placeholder = "") = 0;
    
    // Status bar
    virtual std::string CreateStatusBarItem(const std::string& alignment = "left",
                                              int32_t priority = 0) = 0;
    virtual void SetStatusBarText(const std::string& id, const std::string& text) = 0;
    virtual void SetStatusBarTooltip(const std::string& id, const std::string& tooltip) = 0;
    virtual void DisposeStatusBarItem(const std::string& id) = 0;
    
    // Output channel
    virtual std::string CreateOutputChannel(const std::string& name) = 0;
    virtual void AppendOutput(const std::string& channel, const std::string& text) = 0;
    virtual void AppendLineOutput(const std::string& channel, const std::string& text) = 0;
    virtual void ClearOutput(const std::string& channel) = 0;
    virtual void ShowOutput(const std::string& channel, bool preserveFocus = false) = 0;
    
    // Terminal
    virtual std::string CreateTerminal(const std::string& name,
                                        const std::string& shellPath = "",
                                        const std::vector<std::string>& shellArgs = {}) = 0;
    virtual void SendTerminalText(const std::string& terminal, const std::string& text) = 0;
    virtual void ShowTerminal(const std::string& terminal, bool preserveFocus = false) = 0;
    virtual void DisposeTerminal(const std::string& terminal) = 0;
    
    // Events
    using FileChangeCallback = std::function<void(const std::string& path, const std::string& type)>;
    virtual std::string RegisterFileWatcher(const std::vector<std::string>& patterns,
                                             FileChangeCallback callback) = 0;
    virtual void UnregisterFileWatcher(const std::string& id) = 0;
    
    // Configuration
    virtual std::optional<std::string> GetConfiguration(const std::string& section,
                                                         const std::string& key) = 0;
    virtual bool SetConfiguration(const std::string& section,
                                   const std::string& key,
                                   const std::string& value) = 0;
    
    // Language features
    virtual void RegisterCompletionProvider(const std::string& language,
                                             std::function<std::vector<std::string>(const std::string& prefix)> provider) = 0;
    virtual void RegisterHoverProvider(const std::string& language,
                                          std::function<std::optional<std::string>(const std::string& word)> provider) = 0;
    virtual void RegisterDefinitionProvider(const std::string& language,
                                             std::function<std::optional<std::string>(const std::string& word)> provider) = 0;
    
    // Diagnostics
    virtual void PublishDiagnostics(const std::string& file,
                                      const std::vector<std::unordered_map<std::string, std::string>>& diagnostics) = 0;
    virtual void ClearDiagnostics(const std::string& file) = 0;
    
    // Progress
    virtual std::string CreateProgress(const std::string& title,
                                        const std::optional<std::string>& cancellationToken = std::nullopt) = 0;
    virtual void UpdateProgress(const std::string& id,
                                 const std::optional<std::string>& message = std::nullopt,
                                 const std::optional<double>& increment = std::nullopt) = 0;
    virtual void CompleteProgress(const std::string& id) = 0;
};

// Extension interface
class IExtension {
public:
    virtual ~IExtension() = default;
    
    // Lifecycle
    virtual bool Activate(IExtensionAPI* api, const std::unordered_map<std::string, std::string>& context) = 0;
    virtual void Deactivate() = 0;
    
    // Info
    virtual ExtensionManifest GetManifest() const = 0;
};

// Extension host interface
class IExtensionHost {
public:
    virtual ~IExtensionHost() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& extensions_directory) = 0;
    virtual void Shutdown() = 0;
    
    // Extension management
    virtual bool InstallExtension(const std::string& path_or_id) = 0;
    virtual bool UninstallExtension(const std::string& extension_id) = 0;
    virtual bool EnableExtension(const std::string& extension_id) = 0;
    virtual bool DisableExtension(const std::string& extension_id) = 0;
    virtual bool ActivateExtension(const std::string& extension_id) = 0;
    virtual bool DeactivateExtension(const std::string& extension_id) = 0;
    
    // Queries
    virtual std::vector<ExtensionInfo> ListExtensions() = 0;
    virtual std::optional<ExtensionInfo> GetExtension(const std::string& extension_id) = 0;
    virtual std::vector<ExtensionInfo> GetExtensionsByState(ExtensionState state) = 0;
    virtual bool IsExtensionInstalled(const std::string& extension_id) = 0;
    virtual bool IsExtensionEnabled(const std::string& extension_id) = 0;
    virtual bool IsExtensionActivated(const std::string& extension_id) = 0;
    
    // Marketplace
    virtual std::vector<ExtensionManifest> SearchMarketplace(const std::string& query,
                                                            uint32_t limit = 20) = 0;
    virtual bool DownloadExtension(const std::string& extension_id,
                                    const std::string& version = "") = 0;
    
    // API access
    virtual IExtensionAPI* GetAPI() = 0;
    
    // Events
    using ExtensionChangeCallback = std::function<void(const std::string& extension_id,
                                                         ExtensionState old_state,
                                                         ExtensionState new_state)>;
    virtual void RegisterExtensionChangeCallback(ExtensionChangeCallback callback) = 0;
    
    // Development
    virtual bool LoadExtensionFromPath(const std::string& path) = 0;
    virtual bool ReloadExtension(const std::string& extension_id) = 0;
    virtual std::string GetExtensionLogs(const std::string& extension_id) = 0;
    
    // Statistics
    virtual struct ExtensionStatistics {
        uint32_t total_extensions;
        uint32_t enabled_extensions;
        uint32_t activated_extensions;
        uint32_t builtin_extensions;
        uint32_t marketplace_extensions;
        uint32_t development_extensions;
    } GetStatistics() = 0;
};

// Extension factory function type
using CreateExtensionFunc = IExtension* (*)();
using DestroyExtensionFunc = void (*)(IExtension*);

// Export macros for extensions
#define RAWRXD_EXTENSION_EXPORT extern "C" __declspec(dllexport)

#define RAWRXD_DEFINE_EXTENSION(ExtensionClass) \
    RAWRXD_EXTENSION_EXPORT RawrXD::Developer::IExtension* CreateExtension() { \
        return new ExtensionClass(); \
    } \
    RAWRXD_EXTENSION_EXPORT void DestroyExtension(RawrXD::Developer::IExtension* extension) { \
        delete extension; \
    }

// Global extension host
extern std::unique_ptr<IExtensionHost> g_extension_host;

// Initialize extension host
bool InitializeExtensionHost(const std::string& extensions_directory);
void ShutdownExtensionHost();
bool IsExtensionHostEnabled();

} // namespace Developer
} // namespace RawrXD
