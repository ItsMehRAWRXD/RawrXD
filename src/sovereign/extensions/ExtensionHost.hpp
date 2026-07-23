// ============================================================================
// ExtensionHost.hpp - Extension Host for Plugin System
// Manages extension lifecycle, isolation, and API
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>

namespace Sovereign {

// Extension manifest
struct ExtensionManifest {
    std::string id;
    std::string name;
    std::string version;
    std::string author;
    std::string description;
    std::vector<std::string> contributes; // tools, commands, views, etc.
    std::vector<std::string> dependencies;
    std::string entryPoint;
    std::string apiVersion = "1.0.0";
    bool requiresRestart = false;
};

// Extension API
struct ExtensionAPI {
    // Tool registration
    std::function<bool(const std::string&, const std::string&, 
                       std::function<std::string(const std::string&)>)> registerTool;
    
    // Command registration
    std::function<bool(const std::string&, std::function<void()>)> registerCommand;
    
    // Event subscription
    std::function<bool(const std::string&, std::function<void(const std::string&)>)> onEvent;
    
    // File system access
    std::function<std::string(const std::string&)> readFile;
    std::function<bool(const std::string&, const std::string&)> writeFile;
    
    // Logging
    std::function<void(const std::string&)> log;
    
    // Settings
    std::function<std::string(const std::string&)> getSetting;
    std::function<void(const std::string&, const std::string&)> setSetting;
};

// Extension state
enum class ExtensionState {
    INSTALLED,
    LOADING,
    ACTIVE,
    ERROR,
    DISABLED,
    UNINSTALLED
};

// Extension info
struct ExtensionInfo {
    ExtensionManifest manifest;
    ExtensionState state;
    uint64_t loadTime;
    std::string error;
    size_t memoryUsage;
};

// Extension host
class ExtensionHost {
public:
    ExtensionHost();
    ~ExtensionHost();

    // Extension lifecycle
    bool Install(const ExtensionManifest& manifest);
    bool Uninstall(const std::string& id);
    bool Enable(const std::string& id);
    bool Disable(const std::string& id);
    bool Load(const std::string& id);
    bool Unload(const std::string& id);

    // Extension discovery
    std::vector<ExtensionInfo> ListExtensions() const;
    ExtensionInfo GetExtensionInfo(const std::string& id) const;
    bool IsInstalled(const std::string& id) const;
    bool IsActive(const std::string& id) const;

    // Extension API
    ExtensionAPI GetAPI(const std::string& id);
    void SetAPIImplementation(const ExtensionAPI& api);

    // Event system
    void EmitEvent(const std::string& event, const std::string& data);
    void Subscribe(const std::string& event, std::function<void(const std::string&)> handler);

    // Extension isolation
    bool IsolateExtension(const std::string& id);
    void SetResourceLimit(const std::string& id, size_t memoryMB, uint64_t timeMs);

    // Extension marketplace
    std::vector<ExtensionManifest> SearchMarketplace(const std::string& query);
    bool InstallFromMarketplace(const std::string& id);

    // Statistics
    size_t GetActiveExtensionCount() const;
    size_t GetTotalExtensionCount() const;

    // Persistence
    void SaveExtensions(const std::string& path);
    void LoadExtensions(const std::string& path);

private:
    std::unordered_map<std::string, ExtensionInfo> extensions_;
    std::unordered_map<std::string, std::vector<std::function<void(const std::string&)>>> eventHandlers_;
    ExtensionAPI api_;
    mutable std::mutex mutex_;
    
    bool ValidateManifest(const ExtensionManifest& manifest) const;
    std::string GenerateExtensionPath(const std::string& id) const;
};

} // namespace Sovereign
