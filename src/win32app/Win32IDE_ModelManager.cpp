#include "Win32IDE_ModelManager.h"
#include <filesystem>

namespace ModelManager {

ModelManager& ModelManager::Instance() {
    static ModelManager inst;
    return inst;
}

bool ModelManager::LoadModel(const std::string& modelPath, const std::string& modelName) {
    if (modelPath.empty() || modelName.empty() ||
        !std::filesystem::exists(modelPath) ||
        !std::filesystem::is_regular_file(modelPath)) return false;
    loadedModels_[modelName] = modelPath;
    if (activeModel_.empty()) activeModel_ = modelName;
    return true;
}

bool ModelManager::UnloadModel(const std::string& modelName) {
    auto it = loadedModels_.find(modelName);
    if (it == loadedModels_.end()) return false;
    loadedModels_.erase(it);
    if (activeModel_ == modelName)
        activeModel_ = loadedModels_.empty() ? std::string() : loadedModels_.begin()->first;
    return true;
}

std::vector<std::string> ModelManager::ListModels() const {
    std::vector<std::string> result;
    for (const auto& entry : loadedModels_) result.push_back(entry.first);
    return result;
}

std::string ModelManager::GetActiveModel() const {
    return activeModel_;
}

bool ModelManager::SetActiveModel(const std::string& modelName) {
    if (loadedModels_.find(modelName) == loadedModels_.end()) return false;
    activeModel_ = modelName;
    return true;
}

} // namespace ModelManager
