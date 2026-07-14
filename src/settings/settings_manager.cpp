#include "settings_manager.h"
#include <windows.h>
#include <shlwapi.h>
#include <json/json.h>
#include <fstream>
#include <sstream>

#pragma comment(lib, "shlwapi.lib")

namespace RawrXD {
namespace Settings {

// SettingValue implementation
std::string SettingValue::AsString() const {
    if (type_ == SettingType::String) return stringValue_;
    if (type_ == SettingType::Integer) return std::to_string(intValue_);
    if (type_ == SettingType::Number) return std::to_string(numberValue_);
    if (type_ == SettingType::Boolean) return boolValue_ ? "true" : "false";
    return "";
}

int SettingValue::AsInteger() const {
    if (type_ == SettingType::Integer) return intValue_;
    if (type_ == SettingType::Number) return static_cast<int>(numberValue_);
    if (type_ == SettingType::String) {
        try { return std::stoi(stringValue_); } catch (...) {}
    }
    return 0;
}

double SettingValue::AsNumber() const {
    if (type_ == SettingType::Number) return numberValue_;
    if (type_ == SettingType::Integer) return static_cast<double>(intValue_);
    if (type_ == SettingType::String) {
        try { return std::stod(stringValue_); } catch (...) {}
    }
    return 0.0;
}

bool SettingValue::AsBoolean() const {
    if (type_ == SettingType::Boolean) return boolValue_;
    if (type_ == SettingType::String) {
        return stringValue_ == "true" || stringValue_ == "1" || stringValue_ == "yes";
    }
    if (type_ == SettingType::Integer) return intValue_ != 0;
    return false;
}

std::vector<SettingValue> SettingValue::AsArray() const {
    if (type_ == SettingType::Array) return arrayValue_;
    return {};
}

std::map<std::string, SettingValue> SettingValue::AsObject() const {
    if (type_ == SettingType::Object) return objectValue_;
    return {};
}

// SettingsManager implementation
SettingsManager& SettingsManager::Instance() {
    static SettingsManager instance;
    return instance;
}

bool SettingsManager::Initialize() {
    // Register default settings
    RegisterSetting({SettingKeys::EditorFontSize, "Editor: Font Size", 
                    "Controls the font size in pixels.", SettingType::Integer, SettingValue(14), {}, 8, 72, "editor", 1});
    RegisterSetting({SettingKeys::EditorFontFamily, "Editor: Font Family",
                    "Controls the font family.", SettingType::String, SettingValue("Consolas, 'Courier New', monospace"), {}, 0, 0, "editor", 2});
    RegisterSetting({SettingKeys::EditorTabSize, "Editor: Tab Size",
                    "The number of spaces a tab is equal to.", SettingType::Integer, SettingValue(4), {}, 1, 8, "editor", 3});
    RegisterSetting({SettingKeys::EditorInsertSpaces, "Editor: Insert Spaces",
                    "Insert spaces when pressing Tab.", SettingType::Boolean, SettingValue(true), {}, 0, 0, "editor", 4});
    RegisterSetting({SettingKeys::EditorWordWrap, "Editor: Word Wrap",
                    "Controls how lines should wrap.", SettingType::String, SettingValue("off"), {}, 0, 0, "editor", 5});
    RegisterSetting({SettingKeys::EditorMinimap, "Editor: Minimap",
                    "Controls whether the minimap is shown.", SettingType::Boolean, SettingValue(true), {}, 0, 0, "editor", 6});
    RegisterSetting({SettingKeys::EditorLineNumbers, "Editor: Line Numbers",
                    "Controls the display of line numbers.", SettingType::String, SettingValue("on"), {}, 0, 0, "editor", 7});
    RegisterSetting({SettingKeys::EditorRenderWhitespace, "Editor: Render Whitespace",
                    "Controls how the editor should render whitespace characters.", SettingType::String, SettingValue("selection"), {}, 0, 0, "editor", 8});
    
    RegisterSetting({SettingKeys::WorkbenchTheme, "Workbench: Color Theme",
                    "Specifies the color theme used in the workbench.", SettingType::String, SettingValue("Dark+"), {}, 0, 0, "workbench", 1});
    RegisterSetting({SettingKeys::WorkbenchIconTheme, "Workbench: File Icon Theme",
                    "Specifies the file icon theme.", SettingType::String, SettingValue("Seti"), {}, 0, 0, "workbench", 2});
    
    RegisterSetting({SettingKeys::FilesAutoSave, "Files: Auto Save",
                    "Controls auto save of dirty files.", SettingType::String, SettingValue("off"), {}, 0, 0, "files", 1});
    RegisterSetting({SettingKeys::FilesEncoding, "Files: Encoding",
                    "The default character set encoding.", SettingType::String, SettingValue("utf8"), {}, 0, 0, "files", 2});
    
    RegisterSetting({SettingKeys::TerminalFontSize, "Terminal: Font Size",
                    "Controls the font size in pixels of the terminal.", SettingType::Integer, SettingValue(14), {}, 6, 100, "terminal", 1});
    
    RegisterSetting({SettingKeys::RawrXDInferenceDevice, "RawrXD: Inference Device",
                    "Device to use for AI inference.", SettingType::String, SettingValue("auto"), {}, 0, 0, "rawrxd", 1});
    RegisterSetting({SettingKeys::RawrXDInferenceMaxTokens, "RawrXD: Max Tokens",
                    "Maximum tokens for AI completions.", SettingType::Integer, SettingValue(2048), {}, 1, 8192, "rawrxd", 2});
    RegisterSetting({SettingKeys::RawrXDInferenceTemperature, "RawrXD: Temperature",
                    "Sampling temperature for AI completions.", SettingType::Number, SettingValue(0.7), {}, 0.0, 2.0, "rawrxd", 3});
    
    // Load user settings
    LoadUserSettings();
    
    return true;
}

bool SettingsManager::Shutdown() {
    SaveUserSettings();
    return true;
}

void SettingsManager::RegisterSetting(const SettingDefinition& definition) {
    std::lock_guard<std::mutex> lock(mutex_);
    definitions_[definition.key] = definition;
    defaultSettings_[definition.key] = definition.defaultValue;
}

void SettingsManager::UnregisterSetting(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    definitions_.erase(key);
    defaultSettings_.erase(key);
}

std::vector<SettingDefinition> SettingsManager::GetRegisteredSettings() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<SettingDefinition> result;
    for (const auto& [key, def] : definitions_) {
        result.push_back(def);
    }
    return result;
}

SettingValue SettingsManager::Get(const std::string& key, const SettingValue& defaultValue) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check folder settings
    auto it = folderSettings_.find(key);
    if (it != folderSettings_.end()) return it->second;
    
    // Check workspace settings
    it = workspaceSettings_.find(key);
    if (it != workspaceSettings_.end()) return it->second;
    
    // Check user settings
    it = userSettings_.find(key);
    if (it != userSettings_.end()) return it->second;
    
    // Check default settings
    it = defaultSettings_.find(key);
    if (it != defaultSettings_.end()) return it->second;
    
    return defaultValue;
}

void SettingsManager::Set(const std::string& key, const SettingValue& value, SettingsScope scope) {
    SettingValue oldValue;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        switch (scope) {
            case SettingsScope::User:
                oldValue = userSettings_[key];
                userSettings_[key] = value;
                break;
            case SettingsScope::Workspace:
                oldValue = workspaceSettings_[key];
                workspaceSettings_[key] = value;
                break;
            case SettingsScope::Folder:
                oldValue = folderSettings_[key];
                folderSettings_[key] = value;
                break;
            default:
                return;
        }
    }
    
    NotifyChange(key, value, oldValue);
}

bool SettingsManager::Has(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    return folderSettings_.count(key) > 0 ||
           workspaceSettings_.count(key) > 0 ||
           userSettings_.count(key) > 0 ||
           defaultSettings_.count(key) > 0;
}

void SettingsManager::Remove(const std::string& key, SettingsScope scope) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    switch (scope) {
        case SettingsScope::User:
            userSettings_.erase(key);
            break;
        case SettingsScope::Workspace:
            workspaceSettings_.erase(key);
            break;
        case SettingsScope::Folder:
            folderSettings_.erase(key);
            break;
        default:
            break;
    }
}

std::string SettingsManager::GetString(const std::string& key, const std::string& defaultValue) {
    return Get(key, SettingValue(defaultValue)).AsString();
}

int SettingsManager::GetInteger(const std::string& key, int defaultValue) {
    return Get(key, SettingValue(defaultValue)).AsInteger();
}

double SettingsManager::GetNumber(const std::string& key, double defaultValue) {
    return Get(key, SettingValue(defaultValue)).AsNumber();
}

bool SettingsManager::GetBoolean(const std::string& key, bool defaultValue) {
    return Get(key, SettingValue(defaultValue)).AsBoolean();
}

std::vector<std::string> SettingsManager::GetArray(const std::string& key) {
    auto val = Get(key, SettingValue());
    std::vector<std::string> result;
    for (const auto& v : val.AsArray()) {
        result.push_back(v.AsString());
    }
    return result;
}

void SettingsManager::SetString(const std::string& key, const std::string& value, SettingsScope scope) {
    Set(key, SettingValue(value), scope);
}

void SettingsManager::SetInteger(const std::string& key, int value, SettingsScope scope) {
    Set(key, SettingValue(value), scope);
}

void SettingsManager::SetNumber(const std::string& key, double value, SettingsScope scope) {
    Set(key, SettingValue(value), scope);
}

void SettingsManager::SetBoolean(const std::string& key, bool value, SettingsScope scope) {
    Set(key, SettingValue(value), scope);
}

void SettingsManager::SetArray(const std::string& key, const std::vector<std::string>& value, SettingsScope scope) {
    std::vector<SettingValue> arr;
    for (const auto& s : value) {
        arr.push_back(SettingValue(s));
    }
    Set(key, SettingValue().SetArray(arr), scope);
}

bool SettingsManager::LoadUserSettings() {
    std::string path = GetUserSettingsPath();
    
    std::ifstream file(path);
    if (!file.is_open()) return false;
    
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(file, root)) return false;
    
    std::lock_guard<std::mutex> lock(mutex_);
    userSettings_.clear();
    
    for (const auto& member : root.getMemberNames()) {
        const Json::Value& val = root[member];
        if (val.isString()) {
            userSettings_[member] = SettingValue(val.asString());
        } else if (val.isInt()) {
            userSettings_[member] = SettingValue(val.asInt());
        } else if (val.isDouble()) {
            userSettings_[member] = SettingValue(val.asDouble());
        } else if (val.isBool()) {
            userSettings_[member] = SettingValue(val.asBool());
        }
    }
    
    return true;
}

bool SettingsManager::SaveUserSettings() {
    std::string path = GetUserSettingsPath();
    
    // Ensure directory exists
    char dir[MAX_PATH];
    strcpy_s(dir, path.c_str());
    PathRemoveFileSpecA(dir);
    CreateDirectoryA(dir, nullptr);
    
    Json::Value root;
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [key, value] : userSettings_) {
        switch (value.GetType()) {
            case SettingType::String:
                root[key] = value.AsString();
                break;
            case SettingType::Integer:
                root[key] = value.AsInteger();
                break;
            case SettingType::Number:
                root[key] = value.AsNumber();
                break;
            case SettingType::Boolean:
                root[key] = value.AsBoolean();
                break;
            default:
                break;
        }
    }
    
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "    ";
    file << Json::writeString(builder, root);
    return true;
}

bool SettingsManager::LoadWorkspaceSettings(const std::string& workspacePath) {
    std::string settingsPath = workspacePath + "\\.vscode\\settings.json";
    
    std::ifstream file(settingsPath);
    if (!file.is_open()) return false;
    
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(file, root)) return false;
    
    std::lock_guard<std::mutex> lock(mutex_);
    workspaceSettings_.clear();
    
    for (const auto& member : root.getMemberNames()) {
        const Json::Value& val = root[member];
        if (val.isString()) {
            workspaceSettings_[member] = SettingValue(val.asString());
        } else if (val.isInt()) {
            workspaceSettings_[member] = SettingValue(val.asInt());
        } else if (val.isDouble()) {
            workspaceSettings_[member] = SettingValue(val.asDouble());
        } else if (val.isBool()) {
            workspaceSettings_[member] = SettingValue(val.asBool());
        }
    }
    
    return true;
}

bool SettingsManager::SaveWorkspaceSettings(const std::string& workspacePath) {
    std::string settingsDir = workspacePath + "\\.vscode";
    std::string settingsPath = settingsDir + "\\settings.json";
    
    CreateDirectoryA(settingsDir.c_str(), nullptr);
    
    Json::Value root;
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [key, value] : workspaceSettings_) {
        switch (value.GetType()) {
            case SettingType::String:
                root[key] = value.AsString();
                break;
            case SettingType::Integer:
                root[key] = value.AsInteger();
                break;
            case SettingType::Number:
                root[key] = value.AsNumber();
                break;
            case SettingType::Boolean:
                root[key] = value.AsBoolean();
                break;
            default:
                break;
        }
    }
    
    std::ofstream file(settingsPath);
    if (!file.is_open()) return false;
    
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "    ";
    file << Json::writeString(builder, root);
    return true;
}

bool SettingsManager::CreateProfile(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    SettingsProfile profile;
    profile.name = name;
    profile.id = "profile_" + std::to_string(profiles_.size());
    profile.settings = userSettings_;
    
    profiles_.push_back(profile);
    return true;
}

bool SettingsManager::DeleteProfile(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = std::remove_if(profiles_.begin(), profiles_.end(),
        [&id](const SettingsProfile& p) { return p.id == id; });
    
    if (it == profiles_.end()) return false;
    profiles_.erase(it, profiles_.end());
    return true;
}

bool SettingsManager::SwitchProfile(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& profile : profiles_) {
        if (profile.id == id) {
            currentProfileId_ = id;
            userSettings_ = profile.settings;
            return true;
        }
    }
    return false;
}

std::vector<SettingsProfile> SettingsManager::GetProfiles() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return profiles_;
}

SettingsProfile* SettingsManager::GetCurrentProfile() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& profile : profiles_) {
        if (profile.id == currentProfileId_) {
            return &profile;
        }
    }
    return nullptr;
}

std::map<std::string, SettingValue> SettingsManager::GetAllSettings() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::map<std::string, SettingValue> result = defaultSettings_;
    result.insert(userSettings_.begin(), userSettings_.end());
    result.insert(workspaceSettings_.begin(), workspaceSettings_.end());
    result.insert(folderSettings_.begin(), folderSettings_.end());
    return result;
}

std::map<std::string, SettingValue> SettingsManager::GetSettingsByScope(SettingsScope scope) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    switch (scope) {
        case SettingsScope::Default: return defaultSettings_;
        case SettingsScope::User: return userSettings_;
        case SettingsScope::Workspace: return workspaceSettings_;
        case SettingsScope::Folder: return folderSettings_;
        default: return {};
    }
}

std::string SettingsManager::GetUserSettingsPath() {
    char path[MAX_PATH];
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path);
    PathAppendA(path, "\\RawrXD\\settings.json");
    return std::string(path);
}

void SettingsManager::NotifyChange(const std::string& key, const SettingValue& newValue, const SettingValue& oldValue) {
    if (changeCallback_) {
        changeCallback_(key, newValue, oldValue);
    }
}

} // namespace Settings
} // namespace RawrXD