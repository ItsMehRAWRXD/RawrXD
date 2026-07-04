// ============================================================================
// RawrXD Codex Settings
// Configuration management for Codex module
// ============================================================================

#pragma once
#include "CodexCLI.hpp"
#include <string>
#include <map>
#include <functional>

namespace RawrXD {
namespace Codex {

// Codex configuration settings
struct CodexSettings {
    // Model settings
    std::string model = "gemma3";
    std::string baseUrl = "http://localhost:11434";
    int maxTokens = 2048;
    float temperature = 0.7f;
    float topP = 0.9f;
    int timeoutMs = 30000;
    
    // Feature toggles
    bool enableInlineCompletions = true;
    bool enableChat = true;
    bool enableCodeActions = true;
    bool enableHoverInfo = true;
    bool streamingEnabled = true;
    
    // Autocomplete settings
    float confidenceThreshold = 0.6f;
    int maxContextLines = 20;
    bool mergeWithLSP = true;
    
    // Chat settings
    int maxHistoryMessages = 10;
    std::string systemPrompt;
    bool persistChatHistory = true;
    
    // UI settings
    bool showCodexInStatusBar = true;
    bool enableNotifications = true;
    int suggestionDelayMs = 150;
    
    // Convert to CLI config
    CodexCLI::Config ToCLIConfig() const {
        CodexCLI::Config config;
        config.model = model;
        config.baseUrl = baseUrl;
        config.maxTokens = maxTokens;
        config.temperature = temperature;
        return config;
    }
    
    // Apply CLI config
    void FromCLIConfig(const CodexCLI::Config& config) {
        model = config.model;
        baseUrl = config.baseUrl;
        maxTokens = config.maxTokens;
        temperature = config.temperature;
    }
};

// Settings change callback
using SettingsChangeCallback = std::function<void(const std::string& key, const std::string& value)>;

// Codex Settings Manager
class CodexSettingsManager {
public:
    CodexSettingsManager();
    ~CodexSettingsManager();
    
    // Initialize and load settings
    bool Initialize(const std::string& configPath = "");
    
    // Save settings to disk
    bool Save();
    
    // Get current settings
    const CodexSettings& GetSettings() const { return m_settings; }
    CodexSettings& GetSettingsMutable() { return m_settings; }
    
    // Update individual settings
    void SetModel(const std::string& model);
    void SetBaseUrl(const std::string& url);
    void SetMaxTokens(int tokens);
    void SetTemperature(float temp);
    void SetEnableInlineCompletions(bool enable);
    void SetEnableChat(bool enable);
    void SetConfidenceThreshold(float threshold);
    void SetSystemPrompt(const std::string& prompt);
    
    // Reset to defaults
    void ResetToDefaults();
    
    // Import/Export
    bool ExportToFile(const std::string& path);
    bool ImportFromFile(const std::string& path);
    
    // Callback for settings changes
    void SetChangeCallback(SettingsChangeCallback callback) { m_changeCallback = callback; }
    
    // Get config file path
    std::string GetConfigPath() const { return m_configPath; }

private:
    CodexSettings m_settings;
    std::string m_configPath;
    SettingsChangeCallback m_changeCallback;
    bool m_initialized = false;
    
    // Default config path
    std::string GetDefaultConfigPath();
    
    // Serialize/deserialize
    std::string SerializeToJson() const;
    bool DeserializeFromJson(const std::string& json);
    
    // Notify change
    void NotifyChange(const std::string& key, const std::string& value);
};

} // namespace Codex
} // namespace RawrXD
