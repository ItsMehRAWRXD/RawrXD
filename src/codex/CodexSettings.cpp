// ============================================================================
// RawrXD Codex Settings Implementation
// ============================================================================

#include "CodexSettings.hpp"
#include "JsonLite.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstdlib>

namespace RawrXD {
namespace Codex {

CodexSettingsManager::CodexSettingsManager() = default;
CodexSettingsManager::~CodexSettingsManager() {
    if (m_initialized) {
        Save();
    }
}

bool CodexSettingsManager::Initialize(const std::string& configPath) {
    if (!configPath.empty()) {
        m_configPath = configPath;
    } else {
        m_configPath = GetDefaultConfigPath();
    }
    
    // Try to load existing config
    if (std::filesystem::exists(m_configPath)) {
        std::ifstream file(m_configPath);
        if (file) {
            std::string json((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
            if (!json.empty()) {
                DeserializeFromJson(json);
            }
        }
    }
    
    m_initialized = true;
    return true;
}

bool CodexSettingsManager::Save() {
    if (!m_initialized || m_configPath.empty()) {
        return false;
    }
    
    // Ensure directory exists
    std::filesystem::path path(m_configPath);
    std::filesystem::create_directories(path.parent_path());
    
    std::string json = SerializeToJson();
    std::ofstream file(m_configPath);
    if (!file) {
        return false;
    }
    
    file << json;
    return file.good();
}

void CodexSettingsManager::SetModel(const std::string& model) {
    m_settings.model = model;
    NotifyChange("model", model);
}

void CodexSettingsManager::SetBaseUrl(const std::string& url) {
    m_settings.baseUrl = url;
    NotifyChange("baseUrl", url);
}

void CodexSettingsManager::SetMaxTokens(int tokens) {
    m_settings.maxTokens = tokens;
    NotifyChange("maxTokens", std::to_string(tokens));
}

void CodexSettingsManager::SetTemperature(float temp) {
    m_settings.temperature = temp;
    NotifyChange("temperature", std::to_string(temp));
}

void CodexSettingsManager::SetEnableInlineCompletions(bool enable) {
    m_settings.enableInlineCompletions = enable;
    NotifyChange("enableInlineCompletions", enable ? "true" : "false");
}

void CodexSettingsManager::SetEnableChat(bool enable) {
    m_settings.enableChat = enable;
    NotifyChange("enableChat", enable ? "true" : "false");
}

void CodexSettingsManager::SetConfidenceThreshold(float threshold) {
    m_settings.confidenceThreshold = threshold;
    NotifyChange("confidenceThreshold", std::to_string(threshold));
}

void CodexSettingsManager::SetSystemPrompt(const std::string& prompt) {
    m_settings.systemPrompt = prompt;
    NotifyChange("systemPrompt", prompt);
}

void CodexSettingsManager::ResetToDefaults() {
    m_settings = CodexSettings();
    NotifyChange("reset", "true");
}

bool CodexSettingsManager::ExportToFile(const std::string& path) {
    std::string json = SerializeToJson();
    std::ofstream file(path);
    if (!file) {
        return false;
    }
    file << json;
    return file.good();
}

bool CodexSettingsManager::ImportFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        return false;
    }
    
    std::string json((std::istreambuf_iterator<char>(file)),
                   std::istreambuf_iterator<char>());
    
    if (json.empty()) {
        return false;
    }
    
    return DeserializeFromJson(json);
}

std::string CodexSettingsManager::GetDefaultConfigPath() {
    // Try APPDATA environment variable
    const char* appdata = std::getenv("APPDATA");
    if (appdata) {
        std::string path(appdata);
        path += "\\RawrXD\\codex.json";
        return path;
    }
    
    // Fallback to exe directory
    return "codex.json";
}

std::string CodexSettingsManager::SerializeToJson() const {
    // Build JSON manually for zero-dependency
    std::ostringstream json;
    json << "{\n";
    json << "  \"model\": \"" << m_settings.model << "\",\n";
    json << "  \"baseUrl\": \"" << m_settings.baseUrl << "\",\n";
    json << "  \"maxTokens\": " << m_settings.maxTokens << ",\n";
    json << "  \"temperature\": " << m_settings.temperature << ",\n";
    json << "  \"topP\": " << m_settings.topP << ",\n";
    json << "  \"timeoutMs\": " << m_settings.timeoutMs << ",\n";
    json << "  \"enableInlineCompletions\": " << (m_settings.enableInlineCompletions ? "true" : "false") << ",\n";
    json << "  \"enableChat\": " << (m_settings.enableChat ? "true" : "false") << ",\n";
    json << "  \"enableCodeActions\": " << (m_settings.enableCodeActions ? "true" : "false") << ",\n";
    json << "  \"enableHoverInfo\": " << (m_settings.enableHoverInfo ? "true" : "false") << ",\n";
    json << "  \"streamingEnabled\": " << (m_settings.streamingEnabled ? "true" : "false") << ",\n";
    json << "  \"confidenceThreshold\": " << m_settings.confidenceThreshold << ",\n";
    json << "  \"maxContextLines\": " << m_settings.maxContextLines << ",\n";
    json << "  \"mergeWithLSP\": " << (m_settings.mergeWithLSP ? "true" : "false") << ",\n";
    json << "  \"maxHistoryMessages\": " << m_settings.maxHistoryMessages << ",\n";
    json << "  \"persistChatHistory\": " << (m_settings.persistChatHistory ? "true" : "false") << ",\n";
    json << "  \"showCodexInStatusBar\": " << (m_settings.showCodexInStatusBar ? "true" : "false") << ",\n";
    json << "  \"enableNotifications\": " << (m_settings.enableNotifications ? "true" : "false") << ",\n";
    json << "  \"suggestionDelayMs\": " << m_settings.suggestionDelayMs << ",\n";
    json << "  \"systemPrompt\": \"" << m_settings.systemPrompt << "\"\n";
    json << "}";
    return json.str();
}

bool CodexSettingsManager::DeserializeFromJson(const std::string& json) {
    try {
        auto root = JsonValue::Parse(json);
        
        if (root.HasKey("model")) {
            m_settings.model = root["model"].AsString();
        }
        if (root.HasKey("baseUrl")) {
            m_settings.baseUrl = root["baseUrl"].AsString();
        }
        if (root.HasKey("maxTokens")) {
            m_settings.maxTokens = static_cast<int>(root["maxTokens"].AsNumber());
        }
        if (root.HasKey("temperature")) {
            m_settings.temperature = static_cast<float>(root["temperature"].AsNumber());
        }
        if (root.HasKey("topP")) {
            m_settings.topP = static_cast<float>(root["topP"].AsNumber());
        }
        if (root.HasKey("timeoutMs")) {
            m_settings.timeoutMs = static_cast<int>(root["timeoutMs"].AsNumber());
        }
        if (root.HasKey("enableInlineCompletions")) {
            m_settings.enableInlineCompletions = root["enableInlineCompletions"].AsBool();
        }
        if (root.HasKey("enableChat")) {
            m_settings.enableChat = root["enableChat"].AsBool();
        }
        if (root.HasKey("enableCodeActions")) {
            m_settings.enableCodeActions = root["enableCodeActions"].AsBool();
        }
        if (root.HasKey("enableHoverInfo")) {
            m_settings.enableHoverInfo = root["enableHoverInfo"].AsBool();
        }
        if (root.HasKey("streamingEnabled")) {
            m_settings.streamingEnabled = root["streamingEnabled"].AsBool();
        }
        if (root.HasKey("confidenceThreshold")) {
            m_settings.confidenceThreshold = static_cast<float>(root["confidenceThreshold"].AsNumber());
        }
        if (root.HasKey("maxContextLines")) {
            m_settings.maxContextLines = static_cast<int>(root["maxContextLines"].AsNumber());
        }
        if (root.HasKey("mergeWithLSP")) {
            m_settings.mergeWithLSP = root["mergeWithLSP"].AsBool();
        }
        if (root.HasKey("maxHistoryMessages")) {
            m_settings.maxHistoryMessages = static_cast<int>(root["maxHistoryMessages"].AsNumber());
        }
        if (root.HasKey("persistChatHistory")) {
            m_settings.persistChatHistory = root["persistChatHistory"].AsBool();
        }
        if (root.HasKey("showCodexInStatusBar")) {
            m_settings.showCodexInStatusBar = root["showCodexInStatusBar"].AsBool();
        }
        if (root.HasKey("enableNotifications")) {
            m_settings.enableNotifications = root["enableNotifications"].AsBool();
        }
        if (root.HasKey("suggestionDelayMs")) {
            m_settings.suggestionDelayMs = static_cast<int>(root["suggestionDelayMs"].AsNumber());
        }
        if (root.HasKey("systemPrompt")) {
            m_settings.systemPrompt = root["systemPrompt"].AsString();
        }
        
        return true;
    } catch (...) {
        return false;
    }
}

void CodexSettingsManager::NotifyChange(const std::string& key, const std::string& value) {
    if (m_changeCallback) {
        m_changeCallback(key, value);
    }
}

} // namespace Codex
} // namespace RawrXD
