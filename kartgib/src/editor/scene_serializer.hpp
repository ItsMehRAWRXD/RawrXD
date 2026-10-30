#pragma once

#include "scene.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <glm/glm.hpp>
#include <glm/gtc/quaternion.hpp>

namespace kartgib::editor {

class SceneSerializer {
public:
    static bool saveScene(const Scene& scene, const std::string& path);
    static bool loadScene(Scene& scene, const std::string& path);
    static bool savePrefab(const std::string& entityName, const std::string& path);
    static bool loadPrefab(Scene& scene, const std::string& path, EntityID& outEntity);

private:
    static void serializeEntity(std::ofstream& file, const Scene& scene, EntityID entity, int depth);
    static void serializeComponent(std::ofstream& file, EntityID entity, const std::type_index& type, const Scene& scene);
    static void deserializeEntity(std::ifstream& file, Scene& scene, EntityID& parentEntity);
    static void deserializeComponent(std::ifstream& file, EntityID entity, const std::string& typeName, Scene& scene);
    
    static std::string vec3ToString(const glm::vec3& v);
    static glm::vec3 stringToVec3(const std::string& s);
    static std::string quatToString(const glm::quat& q);
    static glm::quat stringToQuat(const std::string& s);
    static std::string mat4ToString(const glm::mat4& m);
    static glm::mat4 stringToMat4(const std::string& s);
};

} // namespace kartgib::editor