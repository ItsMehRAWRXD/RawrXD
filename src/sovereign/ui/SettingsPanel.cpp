// ============================================================================
// SettingsPanel.cpp - Settings Panel Implementation
// ============================================================================

#include "SettingsPanel.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>

namespace Sovereign {

SettingsPanel::SettingsPanel() = default;
SettingsPanel::~SettingsPanel() { Shutdown(); }

bool SettingsPanel::Initialize(const std::string& configPath) {
    configPath_ = configPath;
    Load();
    return true;
}

void SettingsPanel::Shutdown() { Save(); }

void SettingsPanel::RegisterSection(const SettingsSection& section) {
    std::lock_guard<std::mutex> lock(mutex_);
    sections_[section.name] = section;
    for (const auto& setting : section.settings) {
        flatSettings_[GetFullKey(section.name, setting.key)] = setting;
        stats_.totalSettings++;
    }
}

void SettingsPanel::RegisterSetting(const std::string& section, const SettingDefinition& setting) {
    std::lock_guard<std::mutex> lock(mutex_);
    sections_[section].settings.push_back(setting);
    flatSettings_[GetFullKey(section, setting.key)] = setting;
    stats_.totalSettings++;
}

std::any SettingsPanel::Get(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = flatSettings_.find(key);
    if (it != flatSettings_.end()) return it->second.currentValue.has_value() ? it->second.currentValue : it->second.defaultValue;
    return {};
}

std::string SettingsPanel::GetString(const std::string& key, const std::string& defaultValue) const {
    auto val = Get(key);
    try { return std::any_cast<std::string>(val); } catch (...) { return defaultValue; }
}

int SettingsPanel::GetInt(const std::string& key, int defaultValue) const {
    auto val = Get(key);
    try { return std::any_cast<int>(val); } catch (...) { return defaultValue; }
}

float SettingsPanel::GetFloat(const std::string& key, float defaultValue) const {
    auto val = Get(key);
    try { return std::any_cast<float>(val); } catch (...) { return defaultValue; }
}

bool SettingsPanel::GetBool(const std::string& key, bool defaultValue) const {
    auto val = Get(key);
    try { return std::any_cast<bool>(val); } catch (...) { return defaultValue; }
}

bool SettingsPanel::Set(const std::string& key, const std::any& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = flatSettings_.find(key);
    if (it == flatSettings_.end()) return false;
    it->second.currentValue = value;
    stats_.modifiedSettings++;
    if (changeCallback_) changeCallback_(key, value);
    return true;
}

bool SettingsPanel::SetString(const std::string& key, const std::string& value) { return Set(key, value); }
bool SettingsPanel::SetInt(const std::string& key, int value) { return Set(key, value); }
bool SettingsPanel::SetFloat(const std::string& key, float value) { return Set(key, value); }
bool SettingsPanel::SetBool(const std::string& key, bool value) { return Set(key, value); }

bool SettingsPanel::Reset(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = flatSettings_.find(key);
    if (it == flatSettings_.end()) return false;
    it->second.currentValue = it->second.defaultValue;
    return true;
}

bool SettingsPanel::ResetAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [key, setting] : flatSettings_) setting.currentValue = setting.defaultValue;
    return true;
}

std::vector<SettingsSection> SettingsPanel::GetSections() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<SettingsSection> result;
    for (const auto& [name, section] : sections_) result.push_back(section);
    return result;
}

bool SettingsPanel::Save() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ofstream file(configPath_);
    if (!file) return false;
    
    for (const auto& [key, setting] : flatSettings_) {
        file << key << "=";
        if (setting.currentValue.has_value()) {
            try { file << std::any_cast<std::string>(setting.currentValue); } catch (...) {
                try { file << std::any_cast<int>(setting.currentValue); } catch (...) {
                    try { file << std::any_cast<float>(setting.currentValue); } catch (...) {
                        try { file << (std::any_cast<bool>(setting.currentValue) ? "true" : "false"); } catch (...) {}
                    }
                }
            }
        }
        file << "\n";
    }
    stats_.saves++;
    return true;
}

bool SettingsPanel::Load() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ifstream file(configPath_);
    if (!file) return false;
    
    std::string line;
    while (std::getline(file, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string value = line.substr(eq + 1);
        
        auto it = flatSettings_.find(key);
        if (it != flatSettings_.end()) {
            switch (it->second.type) {
                case SettingType::STRING: it->second.currentValue = value; break;
                case SettingType::INT: it->second.currentValue = std::stoi(value); break;
                case SettingType::FLOAT: it->second.currentValue = std::stof(value); break;
                case SettingType::BOOL: it->second.currentValue = (value == "true"); break;
                default: it->second.currentValue = value; break;
            }
        }
    }
    stats_.loads++;
    return true;
}

std::string SettingsPanel::GetFullKey(const std::string& section, const std::string& key) const {
    return section + "." + key;
}

} // namespace Sovereign
