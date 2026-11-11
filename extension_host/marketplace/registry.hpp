// registry.hpp — Extension Registry
#pragma once
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <functional>

namespace RawrXD {
namespace ExtensionHost {

// ============================================================================
// Registry Entry
// ============================================================================
struct RegistryEntry {
    std::string id;
    std::string name;
    std::string displayName;
    std::string publisher;
    std::string version;
    std::string description;
    std::filesystem::path installPath;
    bool enabled = true;
    bool builtin = false;
    bool hasUpdate = false;
    std::string latestVersion;
    int64_t installTimestamp = 0;
    int64_t lastUsedTimestamp = 0;
};

// ============================================================================
// Extension Registry
// ============================================================================
class ExtensionRegistry {
public:
    static ExtensionRegistry& Get();

    // Initialize registry
    bool Initialize(const std::filesystem::path& registryPath);

    // Register extension
    bool Register(const RegistryEntry& entry);

    // Unregister extension
    bool Unregister(const std::string& extensionId);

    // Get extension info
    RegistryEntry* Get(const std::string& extensionId);
    const RegistryEntry* Get(const std::string& extensionId) const;

    // List all registered extensions
    std::vector<RegistryEntry*> ListAll();
    std::vector<const RegistryEntry*> ListAll() const;

    // List enabled extensions
    std::vector<RegistryEntry*> ListEnabled();

    // List builtin extensions
    std::vector<RegistryEntry*> ListBuiltin();

    // Update extension info
    bool Update(const std::string& extensionId, const RegistryEntry& entry);

    // Check for updates
    bool CheckForUpdate(const std::string& extensionId, const std::string& latestVersion);

    // Persistence
    bool Save();
    bool Load();

    // Events
    using RegistryCallback = std::function<void(const std::string& extensionId)>;
    void OnExtensionAdded(RegistryCallback callback) { m_onAdd = callback; }
    void OnExtensionRemoved(RegistryCallback callback) { m_onRemove = callback; }
    void OnExtensionUpdated(RegistryCallback callback) { m_onUpdate = callback; }

private:
    ExtensionRegistry() = default;
    std::filesystem::path m_registryPath;
    std::map<std::string, RegistryEntry> m_entries;
    RegistryCallback m_onAdd;
    RegistryCallback m_onRemove;
    RegistryCallback m_onUpdate;
};

} // namespace ExtensionHost
} // namespace RawrXD
