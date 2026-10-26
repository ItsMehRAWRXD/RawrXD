#include "editor/scene.hpp"

namespace kartgib::editor {

void Scene::save(const std::string& path) {
    SceneSerializer::saveScene(*this, path);
}

bool Scene::load(const std::string& path) {
    return SceneSerializer::loadScene(*this, path);
}

void Scene::clear() {
    // Clear all entities
    for (size_t i = 1; i < entityManager.entityNames_.size(); ++i) {
        if (!entityManager.entityDestroyed_[i]) {
            entityManager.destroyEntity(static_cast<EntityID>(i));
        }
    }
    rootEntity = INVALID_ENTITY;
    rootEntities.clear();
    name = "Untitled Scene";
    path = "";
    version = 1;
    lastModified = 0;
    description.clear();
}

} // namespace kartgib::editor