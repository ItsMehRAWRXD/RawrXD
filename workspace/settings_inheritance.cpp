// settings_inheritance.cpp — Workspace Settings Inheritance
#include "workspace_manager.hpp"
#include <fstream>
#include <algorithm>

namespace RawrXD {
namespace Workspace {

// ============================================================================
// Settings Inheritance — Layered settings with priority-based resolution
// ============================================================================
class SettingsInheritance {
public:
    static SettingsInheritance& Get();

    // Setting layers (lower index = lower priority)
    enum Layer {
        Default = 0,       // Built-in defaults
        User = 1,          // User-level settings
        Workspace = 2,     // Workspace-level settings
        Folder = 3,        // Folder-level settings
        Project = 4,       // Project-level settings
        Temporary = 5      // Session/temporary overrides
    };

    // Set a value at a specific layer
    void Set(const std::string& key, const std::string& value, Layer layer = User);

    // Get resolved value (highest priority layer wins)
    std::string Get(const std::string& key) const;

    // Get value from specific layer
    std::string GetFromLayer(const std::string& key, Layer layer) const;

    // Check if key exists at any layer
    bool Has(const std::string& key) const;

    // Check if key exists at specific layer
    bool HasAtLayer(const std::string& key, Layer layer) const;

    // Remove from specific layer
    void Remove(const std::string& key, Layer layer);

    // Clear all settings at a layer
    void ClearLayer(Layer layer);

    // Get all settings at a layer
    std::map<std::string, std::string> GetAllAtLayer(Layer layer) const;

    // Get all resolved settings
    std::map<std::string, std::string> GetAll() const;

    // Load settings file into a layer
    bool LoadFile(const std::filesystem::path& path, Layer layer);

    // Save layer to file
    bool SaveFile(const std::filesystem::path& path, Layer layer) const;

    // Layer names for display
    static const char* LayerName(Layer layer);

private:
    SettingsInheritance() = default;
    std::map<Layer, std::map<std::string, std::string>> m_layers;
};

SettingsInheritance& SettingsInheritance::Get() {
    static SettingsInheritance instance;
    return instance;
}

void SettingsInheritance::Set(const std::string& key, const std::string& value, Layer layer) {
    m_layers[layer][key] = value;
}

std::string SettingsInheritance::Get(const std::string& key) const {
    // Check from highest priority to lowest
    for (int l = Temporary; l >= Default; l--) {
        auto layer = static_cast<Layer>(l);
        auto it = m_layers.find(layer);
        if (it != m_layers.end()) {
            auto valIt = it->second.find(key);
            if (valIt != it->second.end()) {
                return valIt->second;
            }
        }
    }
    return {};
}

std::string SettingsInheritance::GetFromLayer(const std::string& key, Layer layer) const {
    auto it = m_layers.find(layer);
    if (it != m_layers.end()) {
        auto valIt = it->second.find(key);
        if (valIt != it->second.end()) {
            return valIt->second;
        }
    }
    return {};
}

bool SettingsInheritance::Has(const std::string& key) const {
    for (int l = Temporary; l >= Default; l--) {
        auto layer = static_cast<Layer>(l);
        auto it = m_layers.find(layer);
        if (it != m_layers.end()) {
            if (it->second.count(key)) return true;
        }
    }
    return false;
}

bool SettingsInheritance::HasAtLayer(const std::string& key, Layer layer) const {
    auto it = m_layers.find(layer);
    if (it != m_layers.end()) {
        return it->second.count(key) > 0;
    }
    return false;
}

void SettingsInheritance::Remove(const std::string& key, Layer layer) {
    auto it = m_layers.find(layer);
    if (it != m_layers.end()) {
        it->second.erase(key);
    }
}

void SettingsInheritance::ClearLayer(Layer layer) {
    m_layers[layer].clear();
}

std::map<std::string, std::string> SettingsInheritance::GetAllAtLayer(Layer layer) const {
    auto it = m_layers.find(layer);
    return it != m_layers.end() ? it->second : std::map<std::string, std::string>{};
}

std::map<std::string, std::string> SettingsInheritance::GetAll() const {
    std::map<std::string, std::string> result;
    for (int l = Default; l <= Temporary; l++) {
        auto layer = static_cast<Layer>(l);
        auto it = m_layers.find(layer);
        if (it != m_layers.end()) {
            for (const auto& [key, value] : it->second) {
                result[key] = value; // Higher layers overwrite lower
            }
        }
    }
    return result;
}

bool SettingsInheritance::LoadFile(const std::filesystem::path& path, Layer layer) {
    if (!std::filesystem::exists(path)) return false;

    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        // Parse "key": "value" pairs
        for (size_t i = 0; i < line.length(); i++) {
            if (line[i] == '"') {
                auto endKey = line.find('"', i + 1);
                if (endKey == std::string::npos) break;
                auto key = line.substr(i + 1, endKey - i - 1);
                auto colon = line.find(':', endKey);
                if (colon == std::string::npos) break;
                auto startVal = line.find('"', colon + 1);
                if (startVal == std::string::npos) break;
                auto endVal = line.find('"', startVal + 1);
                if (endVal == std::string::npos) break;
                auto value = line.substr(startVal + 1, endVal - startVal - 1);
                m_layers[layer][key] = value;
                break;
            }
        }
    }

    return true;
}

bool SettingsInheritance::SaveFile(const std::filesystem::path& path, Layer layer) const {
    std::ofstream file(path);
    if (!file.is_open()) return false;

    file << "{\n";
    auto it = m_layers.find(layer);
    if (it != m_layers.end()) {
        bool first = true;
        for (const auto& [key, value] : it->second) {
            if (!first) file << ",\n";
            first = false;
            file << "  \"" << key << "\": \"" << value << "\"";
        }
    }
    file << "\n}\n";
    return true;
}

const char* SettingsInheritance::LayerName(Layer layer) {
    switch (layer) {
        case Default: return "Default";
        case User: return "User";
        case Workspace: return "Workspace";
        case Folder: return "Folder";
        case Project: return "Project";
        case Temporary: return "Temporary";
        default: return "Unknown";
    }
}

} // namespace Workspace
} // namespace RawrXD
