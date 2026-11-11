#include "Win32IDE_ModelManager.h"

namespace ModelManager {

ModelManager& ModelManager::Instance() {
    static ModelManager inst;
    return inst;
}

bool ModelManager::LoadModel(const std::string& /*modelPath*/, const std::string& /*modelName*/) {
    return false;
}

bool ModelManager::UnloadModel(const std::string& /*modelName*/) {
    return false;
}

std::vector<std::string> ModelManager::ListModels() const {
    return {};
}

std::string ModelManager::GetActiveModel() const {
    return activeModel_;
}

bool ModelManager::SetActiveModel(const std::string& /*modelName*/) {
    return false;
}

} // namespace ModelManager
