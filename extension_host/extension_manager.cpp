// extension_manager.cpp — Extension Host Core Implementation
#include "extension_manager.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <zip.h>  // miniz for VSIX extraction

namespace RawrXD {
namespace ExtensionHost {

// ============================================================================
// ExtensionInstance Implementation
// ============================================================================
ExtensionInstance::ExtensionInstance(const ExtensionManifest& manifest)
    : m_manifest(manifest)
{
}

ExtensionInstance::~ExtensionInstance() {
    if (m_state == ExtensionState::Active) {
        Deactivate();
    }
    Unload();
}

bool ExtensionInstance::Load() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state != ExtensionState::Installed) return false;
    m_state = ExtensionState::Loading;
    // QuickJS runtime creation happens here
    m_state = ExtensionState::Activating;
    return true;
}

bool ExtensionInstance::Activate() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state != ExtensionState::Activating) return false;
    m_state = ExtensionState::Active;
    return true;
}

bool ExtensionInstance::Deactivate() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state != ExtensionState::Active) return false;
    m_state = ExtensionState::Deactivating;
    m_state = ExtensionState::Deactivated;
    return true;
}

void ExtensionInstance::Unload() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state = ExtensionState::Installed;
    m_runtime = nullptr;
}

// ============================================================================
// ExtensionManager Implementation
// ============================================================================
ExtensionManager::ExtensionManager() = default;
ExtensionManager::~ExtensionManager() { Shutdown(); }

bool ExtensionManager::Initialize(const std::filesystem::path& extensionsDir) {
    m_extensionsDir = extensionsDir;
    if (!std::filesystem::exists(m_extensionsDir)) {
        std::filesystem::create_directories(m_extensionsDir);
    }
    ScanExtensions();
    m_initialized = true;
    return true;
}

void ExtensionManager::Shutdown() {
    for (auto& [id, instance] : m_extensions) {
        if (instance->GetState() == ExtensionState::Active) {
            instance->Deactivate();
        }
    }
    m_extensions.clear();
    m_initialized = false;
}

bool ExtensionManager::InstallFromVSIX(const std::filesystem::path& vsixPath) {
    if (!std::filesystem::exists(vsixPath)) return false;

    // Extract VSIX (which is a ZIP file)
    std::string extId;
    std::filesystem::path extractDir = m_extensionsDir / vsixPath.stem();

    // TODO: Use miniz to extract VSIX
    // For now, create directory and placeholder manifest
    std::filesystem::create_directories(extractDir);

    // Load manifest from extracted package
    auto manifest = LoadManifest(extractDir);
    if (!manifest) return false;

    // Check enterprise policy
    if (!IsExtensionAllowed(manifest->id)) return false;

    // Validate signature
    if (!ValidateSignature(extractDir)) return false;

    // Create sandbox permissions from manifest
    PermissionSet perms;
    for (const auto& p : manifest->permissions) {
        if (p == "filesystem.read") perms.filesystemRead = true;
        if (p == "filesystem.write") perms.filesystemWrite = true;
        if (p == "network") perms.network = true;
        if (p == "terminal") perms.terminal = true;
        if (p == "language-server") perms.languageServer = true;
        if (p == "debugger") perms.debugger = true;
    }

    // Create extension instance
    auto instance = std::make_unique<ExtensionInstance>(*manifest);
    if (!CreateSandbox(instance.get())) return false;

    m_extensions[manifest->id] = std::move(instance);
    return true;
}

bool ExtensionManager::Install(const std::string& extensionId) {
    // Marketplace download would happen here
    // For now, check if already installed
    if (m_extensions.find(extensionId) != m_extensions.end()) return true;
    return false;
}

bool ExtensionManager::Uninstall(const std::string& extensionId) {
    auto it = m_extensions.find(extensionId);
    if (it == m_extensions.end()) return false;

    auto* instance = it->second.get();
    if (instance->GetState() == ExtensionState::Active) {
        instance->Deactivate();
    }
    DestroySandbox(instance);

    // Remove extension directory
    std::error_code ec;
    std::filesystem::remove_all(instance->GetManifest().installPath, ec);

    m_extensions.erase(it);
    return true;
}

bool ExtensionManager::SetEnabled(const std::string& extensionId, bool enabled) {
    auto it = m_extensions.find(extensionId);
    if (it == m_extensions.end()) return false;

    if (!enabled && it->second->GetState() == ExtensionState::Active) {
        it->second->Deactivate();
    }
    return true;
}

ExtensionInstance* ExtensionManager::GetExtension(const std::string& extensionId) {
    auto it = m_extensions.find(extensionId);
    return it != m_extensions.end() ? it->second.get() : nullptr;
}

std::vector<ExtensionInstance*> ExtensionManager::ListExtensions() const {
    std::vector<ExtensionInstance*> result;
    for (const auto& [id, instance] : m_extensions) {
        result.push_back(instance.get());
    }
    return result;
}

ExtensionState ExtensionManager::GetExtensionState(const std::string& extensionId) const {
    auto it = m_extensions.find(extensionId);
    return it != m_extensions.end() ? it->second->GetState() : ExtensionState::Error;
}

bool ExtensionManager::ActivateOnEvent(const std::string& activationEvent) {
    bool activated = false;
    for (auto& [id, instance] : m_extensions) {
        const auto& manifest = instance->GetManifest();
        for (const auto& event : manifest.activationEvents) {
            if (event == activationEvent && instance->GetState() == ExtensionState::Activating) {
                if (instance->Activate()) {
                    activated = true;
                    if (m_eventCallback) {
                        m_eventCallback(id, ExtensionState::Active);
                    }
                }
            }
        }
    }
    return activated;
}

bool ExtensionManager::IsActive(const std::string& extensionId) const {
    auto it = m_extensions.find(extensionId);
    return it != m_extensions.end() && it->second->GetState() == ExtensionState::Active;
}

size_t ExtensionManager::GetActiveCount() const {
    size_t count = 0;
    for (const auto& [id, instance] : m_extensions) {
        if (instance->GetState() == ExtensionState::Active) count++;
    }
    return count;
}

void ExtensionManager::SetAllowedExtensions(const std::vector<std::string>& allowed) {
    m_allowedExtensions = allowed;
}

void ExtensionManager::SetBlockedExtensions(const std::vector<std::string>& blocked) {
    m_blockedExtensions = blocked;
}

bool ExtensionManager::IsExtensionAllowed(const std::string& extensionId) const {
    // Check blocked list first
    if (std::find(m_blockedExtensions.begin(), m_blockedExtensions.end(), extensionId) != m_blockedExtensions.end()) {
        return false;
    }
    // If allowed list is non-empty, extension must be in it
    if (!m_allowedExtensions.empty()) {
        return std::find(m_allowedExtensions.begin(), m_allowedExtensions.end(), extensionId) != m_allowedExtensions.end();
    }
    return true;
}

void ExtensionManager::ScanExtensions() {
    if (!std::filesystem::exists(m_extensionsDir)) return;

    for (const auto& entry : std::filesystem::directory_iterator(m_extensionsDir)) {
        if (!entry.is_directory()) continue;

        auto manifest = LoadManifest(entry.path());
        if (!manifest) continue;

        if (!IsExtensionAllowed(manifest->id)) continue;

        auto instance = std::make_unique<ExtensionInstance>(*manifest);
        m_extensions[manifest->id] = std::move(instance);
    }
}

std::optional<ExtensionManifest> ExtensionManager::LoadManifest(const std::filesystem::path& extensionDir) {
    std::filesystem::path manifestPath = extensionDir / "package.json";
    if (!std::filesystem::exists(manifestPath)) {
        // Try extension.json as fallback
        manifestPath = extensionDir / "extension.json";
        if (!std::filesystem::exists(manifestPath)) return std::nullopt;
    }

    std::ifstream file(manifestPath);
    if (!file.is_open()) return std::nullopt;

    // Simple JSON parsing for manifest
    // In production, use nlohmann::json
    ExtensionManifest manifest;
    manifest.installPath = extensionDir;

    std::string line;
    while (std::getline(file, line)) {
        // Parse key-value pairs from JSON
        auto parseStr = [](const std::string& l, const std::string& key) -> std::string {
            auto pos = l.find("\"" + key + "\"");
            if (pos == std::string::npos) return {};
            auto colon = l.find(':', pos);
            if (colon == std::string::npos) return {};
            auto start = l.find('"', colon + 1);
            if (start == std::string::npos) return {};
            auto end = l.find('"', start + 1);
            if (end == std::string::npos) return {};
            return l.substr(start + 1, end - start - 1);
        };

        if (line.find("\"name\"") != std::string::npos) manifest.name = parseStr(line, "name");
        if (line.find("\"publisher\"") != std::string::npos) manifest.publisher = parseStr(line, "publisher");
        if (line.find("\"version\"") != std::string::npos) manifest.version = parseStr(line, "version");
        if (line.find("\"displayName\"") != std::string::npos) manifest.displayName = parseStr(line, "displayName");
        if (line.find("\"description\"") != std::string::npos) manifest.description = parseStr(line, "description");
    }

    if (manifest.name.empty()) return std::nullopt;
    manifest.id = manifest.publisher.empty() ? manifest.name : manifest.publisher + "." + manifest.name;

    return manifest;
}

bool ExtensionManager::ValidateSignature(const std::filesystem::path& extensionDir) {
    // TODO: Implement VSIX signature validation
    // Check for .signature/.manifest files in VSIX
    return true; // Pass for now
}

bool ExtensionManager::CreateSandbox(ExtensionInstance* instance) {
    // TODO: Create sandboxed environment for extension
    return true;
}

void ExtensionManager::DestroySandbox(ExtensionInstance* instance) {
    // TODO: Clean up sandbox resources
}

} // namespace ExtensionHost
} // namespace RawrXD
