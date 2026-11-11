#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include "model_manifest.hpp"

namespace rawrxd {
namespace runtime {

class ModelRegistry {
public:
    ModelRegistry();
    ~ModelRegistry();

    bool scanDirectory(const std::string& path);

    bool registerModel(
        const ModelManifest& manifest
    );

    ModelManifest* find(
        const std::string& name
    );

    std::vector<ModelManifest> list();

    bool remove(
        const std::string& name
    );

    bool loadRegistry(const std::string& configPath);
    bool saveRegistry(const std::string& configPath);

private:
    std::unordered_map<std::string, ModelManifest> models_;
    std::string registryPath_;
    
    bool parseGGUFHeader(const std::string& filePath, ModelManifest& manifest);
};

} // namespace runtime
} // namespace rawrxd