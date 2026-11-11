#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <mutex>

namespace RawrXD {
namespace Settings {

// Setting value types
enum class SettingType {
    String,
    Integer,
    Number,
    Boolean,
    Array,
    Object,
    Null
};

// Setting value container
class SettingValue {
public:
    SettingValue() : type_(SettingType::Null) {}
    SettingValue(const std::string& val) : type_(SettingType::String), stringValue_(val) {}
    SettingValue(int val) : type_(SettingType::Integer), intValue_(val) {}
    SettingValue(double val) : type_(SettingType::Number), numberValue_(val) {}
    SettingValue(bool val) : type_(SettingType::Boolean), boolValue_(val) {}
    
    SettingType GetType() const { return type_; }
    
    std::string AsString() const;
    int AsInteger() const;
    double AsNumber() const;
    bool AsBoolean() const;
    std::vector<SettingValue> AsArray() const;
    std::map<std::string, SettingValue> AsObject() const;
    
    void SetString(const std::string& val) { type_ = SettingType::String; stringValue_ = val; }
    void SetInteger(int val) { type_ = SettingType::Integer; intValue_ = val; }
    void SetNumber(double val) { type_ = SettingType::Number; numberValue_ = val; }
    void SetBoolean(bool val) { type_ = SettingType::Boolean; boolValue_ = val; }
    void SetArray(const std::vector<SettingValue>& val) { type_ = SettingType::Array; arrayValue_ = val; }
    void SetObject(const std::map<std::string, SettingValue>& val) { type_ = SettingType::Object; objectValue_ = val; }
    
private:
    SettingType type_;
    std::string stringValue_;
    int intValue_ = 0;
    double numberValue_ = 0.0;
    bool boolValue_ = false;
    std::vector<SettingValue> arrayValue_;
    std::map<std::string, SettingValue> objectValue_;
};

// Setting definition for UI
struct SettingDefinition {
    std::string key;
    std::string title;
    std::string description;
    SettingType type;
    SettingValue defaultValue;
    std::vector<std::string> enumValues;  // For enum types
    double minValue = 0;                   // For number types
    double maxValue = 100;                 // For number types
    std::string category;                  // UI grouping
    int order = 0;                         // UI ordering
};

// Settings profile
struct SettingsProfile {
    std::string name;
    std::string id;
    std::map<std::string, SettingValue> settings;
    bool isDefault = false;
};

// Settings scope
enum class SettingsScope {
    Default,      // Built-in defaults
    User,         // User settings (%APPDATA%/RawrXD/settings.json)
    Workspace,    // Workspace settings (.vscode/settings.json)
    Folder        // Folder-specific settings
};

// Main settings manager
class SettingsManager {
public:
    static SettingsManager& Instance();
    
    // Lifecycle
    bool Initialize();
    bool Shutdown();
    
    // Setting registration (for extensions)
    void RegisterSetting(const SettingDefinition& definition);
    void UnregisterSetting(const std::string& key);
    std::vector<SettingDefinition> GetRegisteredSettings() const;
    
    // Setting access
    SettingValue Get(const std::string& key, const SettingValue& defaultValue = SettingValue());
    void Set(const std::string& key, const SettingValue& value, SettingsScope scope = SettingsScope::User);
    bool Has(const std::string& key);
    void Remove(const std::string& key, SettingsScope scope = SettingsScope::User);
    
    // Type-specific getters
    std::string GetString(const std::string& key, const std::string& defaultValue = "");
    int GetInteger(const std::string& key, int defaultValue = 0);
    double GetNumber(const std::string& key, double defaultValue = 0.0);
    bool GetBoolean(const std::string& key, bool defaultValue = false);
    std::vector<std::string> GetArray(const std::string& key);
    
    // Type-specific setters
    void SetString(const std::string& key, const std::string& value, SettingsScope scope = SettingsScope::User);
    void SetInteger(const std::string& key, int value, SettingsScope scope = SettingsScope::User);
    void SetNumber(const std::string& key, double value, SettingsScope scope = SettingsScope::User);
    void SetBoolean(const std::string& key, bool value, SettingsScope scope = SettingsScope::User);
    void SetArray(const std::string& key, const std::vector<std::string>& value, SettingsScope scope = SettingsScope::User);
    
    // Configuration files
    bool LoadUserSettings();
    bool SaveUserSettings();
    bool LoadWorkspaceSettings(const std::string& workspacePath);
    bool SaveWorkspaceSettings(const std::string& workspacePath);
    
    // Profiles
    bool CreateProfile(const std::string& name);
    bool DeleteProfile(const std::string& id);
    bool SwitchProfile(const std::string& id);
    std::vector<SettingsProfile> GetProfiles() const;
    SettingsProfile* GetCurrentProfile();
    
    // Inspection
    std::map<std::string, SettingValue> GetAllSettings() const;
    std::map<std::string, SettingValue> GetSettingsByScope(SettingsScope scope) const;
    
    // Events
    using SettingsChangeCallback = std::function<void(const std::string& key, const SettingValue& newValue, const SettingValue& oldValue)>;
    void SetChangeCallback(SettingsChangeCallback callback) { changeCallback_ = callback; }
    
private:
    SettingsManager() = default;
    ~SettingsManager() = default;
    
    std::map<std::string, SettingDefinition> definitions_;
    std::map<std::string, SettingValue> defaultSettings_;
    std::map<std::string, SettingValue> userSettings_;
    std::map<std::string, SettingValue> workspaceSettings_;
    std::map<std::string, SettingValue> folderSettings_;
    
    std::vector<SettingsProfile> profiles_;
    std::string currentProfileId_;
    
    mutable std::mutex mutex_;
    SettingsChangeCallback changeCallback_;
    
    std::string GetUserSettingsPath();
    void NotifyChange(const std::string& key, const SettingValue& newValue, const SettingValue& oldValue);
    SettingValue* GetSettingPtr(const std::string& key, SettingsScope& outScope);
};

// Common setting keys
namespace SettingKeys {
    // Editor
    constexpr const char* EditorFontSize = "editor.fontSize";
    constexpr const char* EditorFontFamily = "editor.fontFamily";
    constexpr const char* EditorTabSize = "editor.tabSize";
    constexpr const char* EditorInsertSpaces = "editor.insertSpaces";
    constexpr const char* EditorWordWrap = "editor.wordWrap";
    constexpr const char* EditorMinimap = "editor.minimap.enabled";
    constexpr const char* EditorLineNumbers = "editor.lineNumbers";
    constexpr const char* EditorRenderWhitespace = "editor.renderWhitespace";
    
    // Workbench
    constexpr const char* WorkbenchTheme = "workbench.colorTheme";
    constexpr const char* WorkbenchIconTheme = "workbench.iconTheme";
    constexpr const char* WorkbenchSidebarLocation = "workbench.tree.indent";
    
    // Files
    constexpr const char* FilesAutoSave = "files.autoSave";
    constexpr const char* FilesExclude = "files.exclude";
    constexpr const char* FilesEncoding = "files.encoding";
    constexpr const char* FilesEol = "files.eol";
    
    // Terminal
    constexpr const char* TerminalShellWindows = "terminal.integrated.shell.windows";
    constexpr const char* TerminalFontSize = "terminal.integrated.fontSize";
    
    // Extensions
    constexpr const char* ExtensionsAutoUpdate = "extensions.autoUpdate";
    constexpr const char* ExtensionsAutoCheckUpdates = "extensions.autoCheckUpdates";
    
    // RawrXD specific
    constexpr const char* RawrXDInferenceDevice = "rawrxd.inference.device";
    constexpr const char* RawrXDInferenceModel = "rawrxd.inference.model";
    constexpr const char* RawrXDInferenceMaxTokens = "rawrxd.inference.maxTokens";
    constexpr const char* RawrXDInferenceTemperature = "rawrxd.inference.temperature";
}

} // namespace Settings
} // namespace RawrXD