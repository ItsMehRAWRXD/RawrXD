// registry.cpp — Extension Registry Implementation
#include "registry.hpp"
#include <fstream>
#include <algorithm>
#include <chrono>

namespace RawrXD {
namespace ExtensionHost {

ExtensionRegistry& ExtensionRegistry::Get() {
    static ExtensionRegistry instance;
    return instance;
}

bool ExtensionRegistry::Initialize(const std::filesystem::path& registryPath) {
    m_registryPath = registryPath;
    if (!std::filesystem::exists(m_registryPath)) {
        std::filesystem::create_directories(m_registryPath.parent_path());
    }
    return Load();
}

bool ExtensionRegistry::Register(const RegistryEntry& entry) {
    if (m_entries.find(entry.id) != m_entries.end()) return false;

    RegistryEntry newEntry = entry;
    newEntry.installTimestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    newEntry.lastUsedTimestamp = newEntry.installTimestamp;

    m_entries[entry.id] = newEntry;
    Save();

    if (m_onAdd) m_onAdd(entry.id);
    return true;
}

bool ExtensionRegistry::Unregister(const std::string& extensionId) {
    auto it = m_entries.find(extensionId);
    if (it == m_entries.end()) return false;

    m_entries.erase(it);
    Save();

    if (m_onRemove) m_onRemove(extensionId);
    return true;
}

RegistryEntry* ExtensionRegistry::Get(const std::string& extensionId) {
    auto it = m_entries.find(extensionId);
    return it != m_entries.end() ? &it->second : nullptr;
}

const RegistryEntry* ExtensionRegistry::Get(const std::string& extensionId) const {
    auto it = m_entries.find(extensionId);
    return it != m_entries.end() ? &it->second : nullptr;
}

std::vector<RegistryEntry*> ExtensionRegistry::ListAll() {
    std::vector<RegistryEntry*> result;
    for (auto& [id, entry] : m_entries) {
        result.push_back(&entry);
    }
    return result;
}

std::vector<const RegistryEntry*> ExtensionRegistry::ListAll() const {
    std::vector<const RegistryEntry*> result;
    for (const auto& [id, entry] : m_entries) {
        result.push_back(&entry);
    }
    return result;
}

std::vector<RegistryEntry*> ExtensionRegistry::ListEnabled() {
    std::vector<RegistryEntry*> result;
    for (auto& [id, entry] : m_entries) {
        if (entry.enabled) result.push_back(&entry);
    }
    return result;
}

std::vector<RegistryEntry*> ExtensionRegistry::ListBuiltin() {
    std::vector<RegistryEntry*> result;
    for (auto& [id, entry] : m_entries) {
        if (entry.builtin) result.push_back(&entry);
    }
    return result;
}

bool ExtensionRegistry::Update(const std::string& extensionId, const RegistryEntry& entry) {
    auto it = m_entries.find(extensionId);
    if (it == m_entries.end()) return false;

    it->second = entry;
    it->second.lastUsedTimestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    Save();

    if (m_onUpdate) m_onUpdate(extensionId);
    return true;
}

bool ExtensionRegistry::CheckForUpdate(const std::string& extensionId, const std::string& latestVersion) {
    auto it = m_entries.find(extensionId);
    if (it == m_entries.end()) return false;

    if (it->second.version != latestVersion) {
        it->second.hasUpdate = true;
        it->second.latestVersion = latestVersion;
        return true;
    }
    return false;
}

bool ExtensionRegistry::Save() {
    if (m_registryPath.empty()) return false;

    std::ofstream file(m_registryPath);
    if (!file.is_open()) return false;

    // Simple JSON serialization
    file << "{\n";
    file << "  \"extensions\": [\n";
    bool first = true;
    for (const auto& [id, entry] : m_entries) {
        if (!first) file << ",\n";
        first = false;
        file << "    {\n";
        file << "      \"id\": \"" << entry.id << "\",\n";
        file << "      \"name\": \"" << entry.name << "\",\n";
        file << "      \"displayName\": \"" << entry.displayName << "\",\n";
        file << "      \"publisher\": \"" << entry.publisher << "\",\n";
        file << "      \"version\": \"" << entry.version << "\",\n";
        file << "      \"enabled\": " << (entry.enabled ? "true" : "false") << ",\n";
        file << "      \"builtin\": " << (entry.builtin ? "true" : "false") << "\n";
        file << "    }";
    }
    file << "\n  ]\n";
    file << "}\n";

    return true;
}

bool ExtensionRegistry::Load() {
    if (m_registryPath.empty() || !std::filesystem::exists(m_registryPath)) return false;

    std::ifstream file(m_registryPath);
    if (!file.is_open()) return false;

    // TODO: Parse JSON registry file
    // For now, just return true (registry will be populated by scanning)
    return true;
}

} // namespace ExtensionHost
} // namespace RawrXD
