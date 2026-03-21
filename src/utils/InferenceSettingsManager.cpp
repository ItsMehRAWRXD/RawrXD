/**
 * InferenceSettingsManager implementation - Phase 2 integration
 * Qt-free version: persistence stubs (no settings_manager), std::vector ops
 */

#include "InferenceSettingsManager.h"

#include <algorithm>
#include <cmath>

namespace RawrXD {

static InferenceSettingsManager* g_instance = nullptr;
static std::mutex g_instanceMutex;

InferenceSettingsManager& InferenceSettingsManager::getInstance()
{
    if (!g_instance) {
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        if (!g_instance) {
            g_instance = new InferenceSettingsManager();
        }
    }
    return *g_instance;
}

InferenceSettingsManager::InferenceSettingsManager()
    : m_initialized(false), m_currentPreset(Balanced)
{
}

InferenceSettingsManager::~InferenceSettingsManager()
{
    if (m_initialized) {
        save();
    }
}

void InferenceSettingsManager::initialize()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_initialized) {
        return;
    }

    load();

    m_initialized = true;
}

void InferenceSettingsManager::applyPreset(Preset preset)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_currentPreset = preset;
    
    switch (preset) {
    case Balanced:
        m_temperature = 0.7;
        m_topP = 0.9;
        m_topK = 40;
        m_maxTokens = 2048;
        m_repetitionPenalty = 1.1;
        break;
    case Performance:
        m_temperature = 0.3;
        m_topP = 0.5;
        m_topK = 20;
        m_maxTokens = 1024;
        m_repetitionPenalty = 1.05;
        break;
    case Quality:
        m_temperature = 0.9;
        m_topP = 0.95;
        m_topK = 60;
        m_maxTokens = 4096;
        m_repetitionPenalty = 1.15;
        break;
    case Custom:
        break;
    }
    
    // presetChanged / settingsChanged: no-op without Qt signals
}

std::string InferenceSettingsManager::getPresetName(Preset preset) const
{
    switch (preset) {
    case Balanced: return "Balanced";
    case Performance: return "Performance";
    case Quality: return "Quality";
    case Custom: return "Custom";
    default: return "Unknown";
    }
}

void InferenceSettingsManager::setCurrentModelPath(const std::string& modelPath)
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_currentModelPath = modelPath;
    }
    
    addRecentModel(modelPath);
    // modelPathChanged / settingsChanged: no-op without Qt signals
}

std::vector<std::string> InferenceSettingsManager::getRecentModels(int maxCount) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (static_cast<int>(m_recentModels.size()) > maxCount) {
        return std::vector<std::string>(m_recentModels.begin(),
                                        m_recentModels.begin() + maxCount);
    }
    return m_recentModels;
}

void InferenceSettingsManager::addRecentModel(const std::string& modelPath)
{
    if (modelPath.empty()) return;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Remove all existing occurrences
    m_recentModels.erase(
        std::remove(m_recentModels.begin(), m_recentModels.end(), modelPath),
        m_recentModels.end());
    
    // Prepend
    m_recentModels.insert(m_recentModels.begin(), modelPath);
    
    // Limit to 20 recent models
    if (m_recentModels.size() > 20) {
        m_recentModels.resize(20);
    }
    
    // recentModelsUpdated: no-op without Qt signals
}

void InferenceSettingsManager::clearRecentModels()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_recentModels.clear();
    // recentModelsUpdated: no-op without Qt signals
}

// Generation parameter setters
void InferenceSettingsManager::setTemperature(double temp)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_temperature = std::clamp(temp, 0.0, 2.0);
    m_currentPreset = Custom;
}

void InferenceSettingsManager::setTopP(double topP)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_topP = std::clamp(topP, 0.0, 1.0);
    m_currentPreset = Custom;
}

void InferenceSettingsManager::setTopK(int topK)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_topK = std::max(1, topK);
    m_currentPreset = Custom;
}

void InferenceSettingsManager::setMaxTokens(int maxTokens)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_maxTokens = std::max(1, maxTokens);
    m_currentPreset = Custom;
}

void InferenceSettingsManager::setRepetitionPenalty(double penalty)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_repetitionPenalty = std::clamp(penalty, 1.0, 2.0);
    m_currentPreset = Custom;
}

void InferenceSettingsManager::setOllamaModelTag(const std::string& tag)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_ollamaModelTag = tag;
}

void InferenceSettingsManager::setUseOllama(bool use)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_useOllama = use;
}

bool InferenceSettingsManager::validateSettings() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    return m_temperature >= 0.0 && m_temperature <= 2.0 &&
           m_topP >= 0.0 && m_topP <= 1.0 &&
           m_topK >= 1 &&
           m_maxTokens >= 1 &&
           m_repetitionPenalty >= 1.0 && m_repetitionPenalty <= 2.0;
}

void InferenceSettingsManager::save()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) return;
    
    saveGenerationParams();
    saveRecentModels();
}

void InferenceSettingsManager::load()
{
    // No lock here — callers (initialize, public load) already hold m_mutex
    loadGenerationParams();
    loadRecentModels();
}

// Persistence stubs — no Qt SettingsManager available

void InferenceSettingsManager::loadGenerationParams()
{
    // Without Qt persistence, just apply defaults
    m_temperature = 0.7;
    m_topP = 0.9;
    m_topK = 40;
    m_maxTokens = 2048;
    m_repetitionPenalty = 1.1;
    m_ollamaModelTag = "llama2";
    m_useOllama = false;
    m_currentModelPath.clear();
    m_currentPreset = Balanced;
}

void InferenceSettingsManager::saveGenerationParams()
{
    // No-op: settings persistence unavailable without Qt
}

void InferenceSettingsManager::loadRecentModels()
{
    // No-op: no persisted recent-models list without Qt
    m_recentModels.clear();
}

void InferenceSettingsManager::saveRecentModels()
{
    // No-op: settings persistence unavailable without Qt
}

nlohmann::json InferenceSettingsManager::exportToJSON() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    nlohmann::json j;
    j["preset"] = static_cast<int>(m_currentPreset);
    j["temperature"] = m_temperature;
    j["topP"] = m_topP;
    j["topK"] = m_topK;
    j["maxTokens"] = m_maxTokens;
    j["repetitionPenalty"] = m_repetitionPenalty;
    j["ollamaModelTag"] = m_ollamaModelTag;
    j["useOllama"] = m_useOllama;
    j["currentModelPath"] = m_currentModelPath;
    j["recentModels"] = m_recentModels;
    
    return j;
}

void InferenceSettingsManager::importFromJSON(const nlohmann::json& j)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (j.contains("preset")) {
        m_currentPreset = static_cast<Preset>(j["preset"].get<int>());
    }
    if (j.contains("temperature")) {
        m_temperature = j["temperature"].get<double>();
    }
    if (j.contains("topP")) {
        m_topP = j["topP"].get<double>();
    }
    if (j.contains("topK")) {
        m_topK = j["topK"].get<int>();
    }
    if (j.contains("maxTokens")) {
        m_maxTokens = j["maxTokens"].get<int>();
    }
    if (j.contains("repetitionPenalty")) {
        m_repetitionPenalty = j["repetitionPenalty"].get<double>();
    }
    if (j.contains("ollamaModelTag")) {
        m_ollamaModelTag = j["ollamaModelTag"].get<std::string>();
    }
    if (j.contains("useOllama")) {
        m_useOllama = j["useOllama"].get<bool>();
    }
    if (j.contains("currentModelPath")) {
        m_currentModelPath = j["currentModelPath"].get<std::string>();
    }
    if (j.contains("recentModels")) {
        m_recentModels = j["recentModels"].get<std::vector<std::string>>();
    }
}

// Signal stubs — no-op without Qt signal/slot infrastructure
void InferenceSettingsManager::settingsChanged() {}
void InferenceSettingsManager::presetChanged(Preset) {}
void InferenceSettingsManager::modelPathChanged(const std::string&) {}
void InferenceSettingsManager::recentModelsUpdated() {}

} // namespace RawrXD

