// settings_ui.hpp — Settings UI Manager
#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <mutex>

namespace RawrXD {
namespace UX {

// ============================================================================
// Setting Type
// ============================================================================
enum class SettingType {
    String,
    Boolean,
    Integer,
    Float,
    Color,
    Enum,
    Array,
    Object
};

// ============================================================================
// Setting Definition
// ============================================================================
struct SettingDefinition {
    std::string id;
    std::string displayName;
    std::string description;
    SettingType type = SettingType::String;
    std::string category;       // "editor", "terminal", "workspace", "extensions", etc.
    std::string defaultValue;
    std::string currentValue;
    std::vector<std::string> enumValues;  // For Enum type
    std::string minValue;       // For Integer/Float
    std::string maxValue;
    std::string placeholder;
    bool requiresRestart = false;
    bool isExperimental = false;
    bool isDeprecated = false;
};

// ============================================================================
// Settings UI Manager
// ============================================================================
class SettingsUIManager {
public:
    static SettingsUIManager& Get();

    // Register a setting
    void RegisterSetting(const SettingDefinition& setting);

    // Get setting definition
    const SettingDefinition* GetSetting(const std::string& id) const;

    // Get all settings
    std::vector<const SettingDefinition*> GetAllSettings() const;

    // Get settings by category
    std::vector<const SettingDefinition*> GetSettingsByCategory(const std::string& category) const;

    // Get all categories
    std::vector<std::string> GetCategories() const;

    // Update setting value
    bool SetValue(const std::string& id, const std::string& value);

    // Get setting value
    std::string GetValue(const std::string& id) const;

    // Reset setting to default
    bool ResetToDefault(const std::string& id);

    // Reset all settings
    void ResetAll();

    // Search settings
    std::vector<const SettingDefinition*> SearchSettings(const std::string& query) const;

    // Filter settings by category and search
    std::vector<const SettingDefinition*> FilterSettings(const std::string& category, const std::string& query = "") const;

    // Modified settings (user has changed from default)
    std::vector<const SettingDefinition*> GetModifiedSettings() const;

    // Events
    using SettingChangeCallback = std::function<void(const std::string& id, const std::string& newValue)>;
    void OnSettingChanged(SettingChangeCallback callback) { m_onChanged = callback; }

    // Built-in settings
    void RegisterBuiltinSettings();

private:
    SettingsUIManager() = default;

    std::map<std::string, SettingDefinition> m_settings;
    SettingChangeCallback m_onChanged;
    mutable std::mutex m_mutex;
};

} // namespace UX
} // namespace RawrXD
