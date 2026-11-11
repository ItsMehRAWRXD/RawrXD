#pragma once

#include <string>
#include <vector>
#include <map>

namespace ModelManager {

class ModelManager {
public:
    static ModelManager& Instance();

    bool LoadModel(const std::string& modelPath, const std::string& modelName);
    bool UnloadModel(const std::string& modelName);
    std::vector<std::string> ListModels() const;
    std::string GetActiveModel() const;
    bool SetActiveModel(const std::string& modelName);

private:
    ModelManager() = default;
    std::map<std::string, std::string> loadedModels_; // name -> path
    std::string activeModel_;
};

} // namespace ModelManager
