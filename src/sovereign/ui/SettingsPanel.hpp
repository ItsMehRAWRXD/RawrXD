// ============================================================================
// SettingsPanel.hpp - Settings Panel for Sovereign IDE
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <any>

namespace Sovereign {

enum class SettingType { STRING, INT, FLOAT, BOOL, COLOR, FONT, PATH, LIST, DROPDOWN };

struct SettingDefinition {
    std::string key;
    std::string section;
    std::string displayName;
    std::string description;
    SettingType type;
    std::any defaultValue;
    std::any currentValue;
    std::vector<std::string> options; // for DROPDOWN
    std::string minValue;
    std::string maxValue;
    bool requiresRestart;
};

struct SettingsSection {
    std::string name;
    std::string displayName;
    std::string icon;
    std::vector<SettingDefinition> settings;
};

class SettingsPanel {
public:
    SettingsPanel();
    ~SettingsPanel();

    bool Initialize(const std::string& configPath = "settings.json");
    void Shutdown();

    void RegisterSection(const SettingsSection& section);
    void RegisterSetting(const std::string& section, const SettingDefinition& setting);

    std::any Get(const std::string& key) const;
    std::string GetString(const std::string& key, const std::string& defaultValue = "") const;
    int GetInt(const std::string& key, int defaultValue = 0) const;
    float GetFloat(const std::string& key, float defaultValue = 0.0f) const;
    bool GetBool(const std::string& key, bool defaultValue = false) const;

    bool Set(const std::string& key, const std::any& value);
    bool SetString(const std::string& key, const std::string& value);
    bool SetInt(const std::string& key, int value);
    bool SetFloat(const std::string& key, float value);
    bool SetBool(const std::string& key, bool value);

    bool Reset(const std::string& key);
    bool ResetSection(const std::string& section);
    bool ResetAll();

    std::vector<SettingsSection> GetSections() const;
    SettingsSection GetSection(const std::string& name) const;
    SettingDefinition GetSetting(const std::string& key) const;
    bool HasSetting(const std::string& key) const;

    bool Save();
    bool Load();
    bool Export(const std::string& path);
    bool Import(const std::string& path);

    void SetChangeCallback(std::function<void(const std::string&, const std::any&)> callback);

    struct SettingsStats {
        uint64_t totalSettings;
        uint64_t modifiedSettings;
        uint64_t saves;
        uint64_t loads;
    };
    SettingsStats GetStats() const { return stats_; }

private:
    std::string configPath_;
    std::unordered_map<std::string, SettingsSection> sections_;
    std::unordered_map<std::string, SettingDefinition> flatSettings_;
    SettingsStats stats_;
    std::function<void(const std::string&, const std::any&)> changeCallback_;
    mutable std::mutex mutex_;
    
    std::string GetFullKey(const std::string& section, const std::string& key) const;
};

} // namespace Sovereign
