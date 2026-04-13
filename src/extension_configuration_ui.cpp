// ============================================================================
// extension_configuration_ui.cpp — Extension Configuration UI Implementation
// ============================================================================
// Architecture: C++20 | Win32 | No exceptions | Schema validation
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// ============================================================================

#include "extension_configuration_ui.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <regex>
#include <mutex>

namespace RawrXD {
namespace Extensions {

// ============================================================================
// Global Instance
// ============================================================================

static ExtensionConfigurationUI* g_configUI = nullptr;

ExtensionConfigurationUI& GetConfigurationUI() {
    if (!g_configUI) {
        g_configUI = new ExtensionConfigurationUI();
    }
    return *g_configUI;
}

// ============================================================================
// ExtensionConfigurationUI Implementation
// ============================================================================

ExtensionConfigurationUI::ExtensionConfigurationUI() {
}

ExtensionConfigurationUI::~ExtensionConfigurationUI() {
}

bool ExtensionConfigurationUI::RegisterConfigurationSchema(
    const std::string& extensionId,
    const std::vector<ConfigurationSchemaEntry>& schema
) {
    if (extensionId.empty() || schema.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_lock);
    m_schemas[extensionId] = schema;

    // Initialize with defaults
    for (const auto& entry : schema) {
        if (!entry.defaultValue.is_null()) {
            ConfigurationValue cfgVal;
            cfgVal.key = entry.key;
            cfgVal.value = entry.defaultValue;
            cfgVal.scope = ConfigScope::User;
            m_values[entry.key] = cfgVal;
        }
    }

    return true;
}

bool ExtensionConfigurationUI::GetConfiguration(const std::string& key,
                                                ConfigScope scope,
                                                json& outValue) {
    if (key.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_lock);

    auto it = m_values.find(key);
    if (it != m_values.end() && it->second.scope == scope) {
        outValue = it->second.value;
        return true;
    }

    return false;
}

bool ExtensionConfigurationUI::SetConfiguration(const std::string& key,
                                                ConfigScope scope,
                                                const json& value) {
    if (key.empty()) {
        return false;
    }

    // Validate value
    std::string errorMsg;
    if (!ValidateConfigurationValue(key, value, errorMsg)) {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(m_lock);

        ConfigurationValue cfgVal;
        cfgVal.key = key;
        cfgVal.value = value;
        cfgVal.scope = scope;
        m_values[key] = cfgVal;
    }

    NotifyConfigurationChanged(key, value);
    return true;
}

std::vector<ConfigurationValue> ExtensionConfigurationUI::GetExtensionConfiguration(
    const std::string& extensionId,
    ConfigScope scope
) {
    if (extensionId.empty()) {
        return {};
    }

    std::lock_guard<std::mutex> lock(m_lock);

    std::vector<ConfigurationValue> result;
    auto schemaIt = m_schemas.find(extensionId);
    if (schemaIt == m_schemas.end()) {
        return result;
    }

    for (const auto& schemaEntry : schemaIt->second) {
        auto valueIt = m_values.find(schemaEntry.key);
        if (valueIt != m_values.end() && valueIt->second.scope == scope) {
            result.push_back(valueIt->second);
        } else if (!schemaEntry.defaultValue.is_null()) {
            // Return default if not explicitly set
            ConfigurationValue defaultVal;
            defaultVal.key = schemaEntry.key;
            defaultVal.value = schemaEntry.defaultValue;
            defaultVal.scope = scope;
            result.push_back(defaultVal);
        }
    }

    return result;
}

bool ExtensionConfigurationUI::ResetConfiguration(const std::string& key) {
    if (key.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_lock);

    auto it = m_values.find(key);
    if (it != m_values.end()) {
        m_values.erase(it);
        return true;
    }

    return false;
}

std::vector<ConfigurationSchemaEntry> ExtensionConfigurationUI::GetConfigurationSchema(
    const std::string& extensionId
) const {
    if (extensionId.empty()) {
        return {};
    }

    std::lock_guard<std::mutex> lock(m_lock);

    auto it = m_schemas.find(extensionId);
    if (it != m_schemas.end()) {
        return it->second;
    }

    return {};
}

std::unordered_map<std::string, std::vector<ConfigurationSchemaEntry>>
ExtensionConfigurationUI::GetGroupedConfigurationSchema(
    const std::string& extensionId
) const {
    std::unordered_map<std::string, std::vector<ConfigurationSchemaEntry>> grouped;

    auto schema = GetConfigurationSchema(extensionId);
    for (const auto& entry : schema) {
        grouped[entry.category].push_back(entry);
    }

    return grouped;
}

bool ExtensionConfigurationUI::ValidateConfigurationValue(
    const std::string& key,
    const json& value,
    std::string& outErrorMessage
) {
    if (key.empty()) {
        outErrorMessage = "Configuration key is empty";
        return false;
    }

    std::lock_guard<std::mutex> lock(m_lock);

    auto schemaEntry = FindSchemaEntry(key);
    if (!schemaEntry) {
        outErrorMessage = "Configuration key not found: " + key;
        return false;
    }

    if (!ValidateValue(*schemaEntry, value)) {
        outErrorMessage = "Invalid value for configuration: " + key;
        return false;
    }

    return true;
}

void ExtensionConfigurationUI::OnConfigurationChanged(
    const std::string& extensionId,
    std::function<void(const std::string&, const json&)> callback
) {
    if (extensionId.empty()) return;

    std::lock_guard<std::mutex> lock(m_lock);
    m_changeCallbacks[extensionId] = callback;
}

bool ExtensionConfigurationUI::LoadConfiguration(const std::string& storagePath) {
    if (storagePath.empty()) {
        return false;
    }

    try {
        std::ifstream file(storagePath);
        if (!file.is_open()) {
            return true;  // File doesn't exist yet
        }

        json data;
        file >> data;
        file.close();

        std::lock_guard<std::mutex> lock(m_lock);

        if (data.contains("configurations") && data["configurations"].is_array()) {
            for (const auto& item : data["configurations"]) {
                if (item.contains("key") && item.contains("value")) {
                    ConfigurationValue cfgVal;
                    cfgVal.key = item["key"].get<std::string>();
                    cfgVal.value = item["value"];
                    // TODO: Deserialize scope
                    m_values[cfgVal.key] = cfgVal;
                }
            }
        }

        return true;
    } catch (...) {
        return false;
    }
}

bool ExtensionConfigurationUI::SaveConfiguration(const std::string& storagePath) {
    if (storagePath.empty()) {
        return false;
    }

    try {
        json data;
        data["configurations"] = json::array();

        {
            std::lock_guard<std::mutex> lock(m_lock);

            for (const auto& [key, cfgVal] : m_values) {
                json item;
                item["key"] = cfgVal.key;
                item["value"] = cfgVal.value;
                // TODO: Serialize scope
                data["configurations"].push_back(item);
            }
        }

        std::ofstream file(storagePath);
        if (!file.is_open()) {
            return false;
        }

        file << data.dump(2);
        file.close();

        return true;
    } catch (...) {
        return false;
    }
}

ConfigurationSchemaEntry* ExtensionConfigurationUI::FindSchemaEntry(const std::string& key) {
    // Search all schemas for this entry
    for (auto& [extId, schema] : m_schemas) {
        for (auto& entry : schema) {
            if (entry.key == key) {
                return &entry;
            }
        }
    }
    return nullptr;
}

bool ExtensionConfigurationUI::ValidateValue(const ConfigurationSchemaEntry& schema,
                                             const json& value) {
    if (value.is_null() && schema.required) {
        return false;
    }

    if (value.is_null()) {
        return true;  // Null is OK if not required
    }

    // Type checking
    switch (schema.type) {
        case ConfigValueType::String:
            if (!value.is_string()) return false;
            // Check pattern if provided
            if (!schema.pattern.empty()) {
                try {
                    std::regex regex(schema.pattern);
                    return std::regex_match(value.get<std::string>(), regex);
                } catch (...) {
                    return false;
                }
            }
            return true;

        case ConfigValueType::Number:
        case ConfigValueType::Integer:
            if (!value.is_number()) return false;
            // Check min/max if provided
            if (schema.minimum.is_number() && value.get<double>() < schema.minimum.get<double>()) {
                return false;
            }
            if (schema.maximum.is_number() && value.get<double>() > schema.maximum.get<double>()) {
                return false;
            }
            return true;

        case ConfigValueType::Boolean:
            return value.is_boolean();

        case ConfigValueType::Array:
            if (!value.is_array()) return false;
            // TODO: Validate array items
            return true;

        case ConfigValueType::Object:
            return value.is_object();

        default:
            return false;
    }
}

json ExtensionConfigurationUI::ApplyDefaults(const std::string& extensionId) {
    json result = json::object();
    auto schema = GetConfigurationSchema(extensionId);
    for (const auto& entry : schema) {
        if (!entry.defaultValue.is_null()) {
            result[entry.key] = entry.defaultValue;
        }
    }
    return result;
}

void ExtensionConfigurationUI::NotifyConfigurationChanged(const std::string& key,
                                                          const json& newValue) {
    // Extract extension ID from configuration key (e.g., "myext.setting1" -> "myext")
    size_t dotPos = key.find('.');
    if (dotPos != std::string::npos) {
        std::string extId = key.substr(0, dotPos);

        std::lock_guard<std::mutex> lock(m_lock);

        auto it = m_changeCallbacks.find(extId);
        if (it != m_changeCallbacks.end() && it->second) {
            it->second(key, newValue);
        }
    }
}

// ============================================================================
// ExtensionSettingsPanel Implementation
// ============================================================================

ExtensionSettingsPanel::ExtensionSettingsPanel(ExtensionConfigurationUI* configUI)
    : m_configUI(configUI) {
}

ExtensionSettingsPanel::~ExtensionSettingsPanel() {
}

bool ExtensionSettingsPanel::RenderSettingsPanel(const std::string& extensionId) {
    if (!m_configUI || extensionId.empty()) {
        return false;
    }

    auto schema = m_configUI->GetConfigurationSchema(extensionId);
    if (schema.empty()) {
        return false;
    }

    // TODO: Render actual UI based on schema
    // For MVP, this is just a stub

    return true;
}

std::string ExtensionSettingsPanel::GetPanelTitle(const std::string& extensionId) const {
    return "Settings for " + extensionId;
}

bool ExtensionSettingsPanel::ApplyChanges(const std::string& extensionId,
                                          const std::vector<ConfigurationValue>& changes) {
    if (!m_configUI) {
        return false;
    }

    for (const auto& change : changes) {
        m_configUI->SetConfiguration(change.key, change.scope, change.value);
    }

    return true;
}

std::string ExtensionSettingsPanel::RenderStringControl(
    const ConfigurationSchemaEntry& schema) {
    // TODO: Render string input control
    return "";
}

std::string ExtensionSettingsPanel::RenderNumberControl(
    const ConfigurationSchemaEntry& schema) {
    // TODO: Render number input control
    return "";
}

std::string ExtensionSettingsPanel::RenderBooleanControl(
    const ConfigurationSchemaEntry& schema) {
    // TODO: Render checkbox control
    return "";
}

std::string ExtensionSettingsPanel::RenderEnumControl(
    const ConfigurationSchemaEntry& schema) {
    // TODO: Render dropdown control
    return "";
}

std::string ExtensionSettingsPanel::RenderArrayControl(
    const ConfigurationSchemaEntry& schema) {
    // TODO: Render array editor control
    return "";
}

// ============================================================================
// Global Helpers
// ============================================================================

bool GetExtensionSetting(const std::string& key, json& outValue) {
    return GetConfigurationUI().GetConfiguration(key, ConfigScope::User, outValue);
}

bool SetExtensionSetting(const std::string& key, const json& value) {
    return GetConfigurationUI().SetConfiguration(key, ConfigScope::User, value);
}

}  // namespace Extensions
}  // namespace RawrXD

// ============================================================================
// End of extension_configuration_ui.cpp
// ============================================================================
