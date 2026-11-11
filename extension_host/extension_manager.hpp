// extension_manager.hpp — Extension Host Core
// Manages VS Code extension lifecycle, VSIX loading, sandbox, and API surface
// Pure C++20 / Win32 — Zero Qt Dependencies
#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <filesystem>
#include <optional>

namespace RawrXD {
namespace ExtensionHost {

// ============================================================================
// Extension Manifest
// ============================================================================
struct ExtensionManifest {
    std::string id;                    // "publisher.name"
    std::string name;
    std::string displayName;
    std::string publisher;
    std::string version;
    std::string description;
    std::vector<std::string> engines;   // vscode engine versions
    std::vector<std::string> activationEvents;
    std::vector<std::string> permissions;
    std::vector<std::string> dependencies;
    std::filesystem::path installPath;
    bool enabled = true;
    bool builtin = false;
};

// ============================================================================
// Extension State
// ============================================================================
enum class ExtensionState {
    Installed,
    Loading,
    Activating,
    Active,
    Deactivating,
    Deactivated,
    Error,
    Disabled
};

// ============================================================================
// Permission Set
// ============================================================================
struct PermissionSet {
    bool filesystemRead = false;
    bool filesystemWrite = false;
    bool network = false;
    bool terminal = false;
    bool clipboard = false;
    bool languageServer = false;
    bool debugger = false;
    bool workspaceConfiguration = false;
    bool machineLearning = false;
};

// ============================================================================
// Extension Instance
// ============================================================================
class ExtensionInstance {
public:
    ExtensionInstance(const ExtensionManifest& manifest);
    ~ExtensionInstance();

    const ExtensionManifest& GetManifest() const { return m_manifest; }
    ExtensionState GetState() const { return m_state; }
    const PermissionSet& GetPermissions() const { return m_permissions; }

    bool Load();
    bool Activate();
    bool Deactivate();
    void Unload();

    // QuickJS runtime handle
    void* GetRuntime() const { return m_runtime; }
    void SetRuntime(void* rt) { m_runtime = rt; }

private:
    ExtensionManifest m_manifest;
    ExtensionState m_state = ExtensionState::Installed;
    PermissionSet m_permissions;
    void* m_runtime = nullptr;  // QuickJS runtime pointer
    std::mutex m_mutex;
};

// ============================================================================
// Extension Manager
// ============================================================================
class ExtensionManager {
public:
    ExtensionManager();
    ~ExtensionManager();

    // Initialize the extension host
    bool Initialize(const std::filesystem::path& extensionsDir);

    // Shutdown all extensions
    void Shutdown();

    // Install extension from VSIX
    bool InstallFromVSIX(const std::filesystem::path& vsixPath);

    // Install extension from marketplace
    bool Install(const std::string& extensionId);

    // Uninstall extension
    bool Uninstall(const std::string& extensionId);

    // Enable/disable extension
    bool SetEnabled(const std::string& extensionId, bool enabled);

    // Get extension by ID
    ExtensionInstance* GetExtension(const std::string& extensionId);

    // List all installed extensions
    std::vector<ExtensionInstance*> ListExtensions() const;

    // Get extension state
    ExtensionState GetExtensionState(const std::string& extensionId) const;

    // Activate extension by activation event
    bool ActivateOnEvent(const std::string& activationEvent);

    // Check if extension is active
    bool IsActive(const std::string& extensionId) const;

    // Get total count
    size_t GetCount() const { return m_extensions.size(); }

    // Get active count
    size_t GetActiveCount() const;

    // Extension event callbacks
    using ExtensionEventCallback = std::function<void(const std::string& extensionId, ExtensionState state)>;
    void SetEventCallback(ExtensionEventCallback callback) { m_eventCallback = callback; }

    // Enterprise policy integration
    void SetAllowedExtensions(const std::vector<std::string>& allowed);
    void SetBlockedExtensions(const std::vector<std::string>& blocked);
    bool IsExtensionAllowed(const std::string& extensionId) const;

private:
    // Scan extensions directory
    void ScanExtensions();

    // Load extension manifest
    std::optional<ExtensionManifest> LoadManifest(const std::filesystem::path& extensionDir);

    // Validate extension signature
    bool ValidateSignature(const std::filesystem::path& extensionDir);

    // Create sandbox for extension
    bool CreateSandbox(ExtensionInstance* instance);

    // Destroy sandbox
    void DestroySandbox(ExtensionInstance* instance);

    std::filesystem::path m_extensionsDir;
    std::map<std::string, std::unique_ptr<ExtensionInstance>> m_extensions;
    std::vector<std::string> m_allowedExtensions;
    std::vector<std::string> m_blockedExtensions;
    ExtensionEventCallback m_eventCallback;
    mutable std::mutex m_mutex;
    std::atomic<bool> m_initialized{false};
};

} // namespace ExtensionHost
} // namespace RawrXD
