#include "scene_serializer.hpp"
#include <algorithm>
#include <cstring>

namespace kartgib::editor {

bool SceneSerializer::saveScene(const Scene& scene, const std::string& path) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    // Write header
    file.write("KSCENE", 6);
    uint32_t version = 1;
    file.write(reinterpret_cast<const char*>(&version), sizeof(version));

    // Write scene metadata
    uint32_t nameLen = static_cast<uint32_t>(scene.name.size());
    file.write(reinterpret_cast<const char*>(&nameLen), sizeof(nameLen));
    file.write(scene.name.c_str(), nameLen);

    // Write root entity
    uint64_t rootEntity = scene.rootEntity;
    file.write(reinterpret_cast<const char*>(&rootEntity), sizeof(rootEntity));

    // Write all entities
    uint32_t entityCount = static_cast<uint32_t>(scene.entityManager.entityNames_.size());
    file.write(reinterpret_cast<const char*>(&entityCount), sizeof(entityCount));

    for (size_t i = 1; i < scene.entityManager.entityNames_.size(); ++i) {
        if (scene.entityManager.entityDestroyed_[i]) continue;
        
        EntityID entity = static_cast<EntityID>(i);
        serializeEntity(file, scene, entity, 0);
    }

    return true;
}

bool SceneSerializer::loadScene(Scene& scene, const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    // Read header
    char header[6] = {};
    file.read(header, 6);
    if (std::string(header, 6) != "KSCENE") return false;

    uint32_t version = 0;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));

    // Clear current scene
    scene.clear();

    // Read scene metadata
    uint32_t nameLen = 0;
    file.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
    scene.name.resize(nameLen);
    file.read(&scene.name[0], nameLen);

    // Write root entity
    file.read(reinterpret_cast<char*>(&scene.rootEntity), sizeof(scene.rootEntity));

    // Read all entities
    uint32_t entityCount = 0;
    file.read(reinterpret_cast<char*>(&entityCount), sizeof(entityCount));

    for (uint32_t i = 0; i < entityCount; ++i) {
        EntityID entity = INVALID_ENTITY;
        deserializeEntity(file, scene, entity);
    }

    // Re-establish parent-child relationships
    // This would be done during deserialization

    return true;
}

void SceneSerializer::serializeEntity(std::ofstream& file, const Scene& scene, EntityID entity, int depth) {
    // Write entity ID
    file.write(reinterpret_cast<const char*>(&entity), sizeof(entity));

    // Write name
    const std::string& name = scene.entityManager.getName(entity);
    uint32_t nameLen = static_cast<uint32_t>(name.size());
    file.write(reinterpret_cast<const char*>(&nameLen), sizeof(nameLen));
    file.write(name.c_str(), nameLen);

    // Write parent
    EntityID parent = scene.entityManager.getParent(entity);
    file.write(reinterpret_cast<const char*>(&parent), sizeof(parent));

    // Write active state
    bool active = scene.entityManager.isActive(entity);
    file.write(reinterpret_cast<const char*>(&active), sizeof(active));

    // Write components
    uint32_t componentCount = scene.componentManager.getComponentCount(entity);
    file.write(reinterpret_cast<const char*>(&componentCount), sizeof(componentCount));

    const auto& components = scene.entityManager.getComponents(entity);
    for (const auto& type : components) {
        serializeComponent(file, entity, type, scene);
    }

    // Write children
    const auto& children = scene.entityManager.getChildren(entity);
    uint32_t childCount = static_cast<uint32_t>(children.size());
    file.write(reinterpret_cast<const char*>(&childCount), sizeof(childCount));
    for (EntityID child : children) {
        serializeEntity(file, scene, child, depth + 1);
    }
}

void SceneSerializer::serializeComponent(std::ofstream& file, EntityID entity, const std::type_index& type, const Scene& scene) {
    // Write type name hash
    std::string typeName = type.name();
    uint32_t typeLen = static_cast<uint32_t>(typeName.size());
    file.write(reinterpret_cast<const char*>(&typeLen), sizeof(typeLen));
    file.write(typeName.c_str(), typeLen);

    // Serialize based on type
    if (type == typeid(TransformComponent)) {
        auto* comp = scene.componentManager.getComponent<TransformComponent>(entity);
        if (comp) {
            file.write(reinterpret_cast<const char*>(comp->position), sizeof(comp->position));
            file.write(reinterpret_cast<const char*>(comp->rotation), sizeof(comp->rotation));
            file.write(reinterpret_cast<const char*>(comp->scale), sizeof(comp->scale));
            file.write(reinterpret_cast<const char*>(&comp->dirty), sizeof(comp->dirty));
        }
    } else if (type == typeid(NameComponent)) {
        auto* comp = scene.componentManager.getComponent<NameComponent>(entity);
        if (comp) {
            uint32_t nameLen = static_cast<uint32_t>(std::strlen(comp->name));
            file.write(reinterpret_cast<const char*>(&nameLen), sizeof(nameLen));
            file.write(comp->name, nameLen);
        }
    } else if (type == typeid(TagComponent)) {
        auto* comp = scene.componentManager.getComponent<TagComponent>(entity);
        if (comp) {
            uint32_t tagLen = static_cast<uint32_t>(std::strlen(comp->tag));
            file.write(reinterpret_cast<const char*>(&tagLen), sizeof(tagLen));
            file.write(comp->tag, tagLen);
        }
    } else if (type == typeid(MeshRendererComponent)) {
        auto* comp = scene.componentManager.getComponent<MeshRendererComponent>(entity);
        if (comp) {
            file.write(reinterpret_cast<const char*>(&comp->meshID), sizeof(comp->meshID));
            file.write(reinterpret_cast<const char*>(&comp->materialID), sizeof(comp->materialID));
            file.write(reinterpret_cast<const char*>(&comp->visible), sizeof(comp->visible));
            file.write(reinterpret_cast<const char*>(&comp->castShadows), sizeof(comp->castShadows));
            file.write(reinterpret_cast<const char*>(&comp->receiveShadows), sizeof(comp->receiveShadows));
        }
    } else if (type == typeid(CameraComponent)) {
        auto* comp = scene.componentManager.getComponent<CameraComponent>(entity);
        if (comp) {
            file.write(reinterpret_cast<const char*>(&comp->fov), sizeof(comp->fov));
            file.write(reinterpret_cast<const char*>(&comp->nearPlane), sizeof(comp->nearPlane));
            file.write(reinterpret_cast<const char*>(&comp->farPlane), sizeof(comp->farPlane));
            file.write(reinterpret_cast<const char*>(&comp->aspectRatio), sizeof(comp->aspectRatio));
            file.write(reinterpret_cast<const char*>(&comp->isMain), sizeof(comp->isMain));
            file.write(reinterpret_cast<const char*>(&comp->orthographic), sizeof(comp->orthographic));
            file.write(reinterpret_cast<const char*>(&comp->orthoSize), sizeof(comp->orthoSize));
        }
    } else if (type == typeid(LightComponent)) {
        auto* comp = scene.componentManager.getComponent<LightComponent>(entity);
        if (comp) {
            uint8_t typeVal = static_cast<uint8_t>(comp->type);
            file.write(reinterpret_cast<const char*>(&typeVal), sizeof(typeVal));
            file.write(reinterpret_cast<const char*>(comp->color), sizeof(comp->color));
            file.write(reinterpret_cast<const char*>(&comp->intensity), sizeof(comp->intensity));
            file.write(reinterpret_cast<const char*>(&comp->range), sizeof(comp->range));
            file.write(reinterpret_cast<const char*>(&comp->spotAngle), sizeof(comp->spotAngle));
            file.write(reinterpret_cast<const char*>(&comp->innerAngle), sizeof(comp->innerAngle));
            file.write(reinterpret_cast<const char*>(&comp->castShadows), sizeof(comp->castShadows));
            file.write(reinterpret_cast<const char*>(&comp->shadowBias), sizeof(comp->shadowBias));
        }
    } else if (type == typeid(RigidBodyComponent)) {
        auto* comp = scene.componentManager.getComponent<RigidBodyComponent>(entity);
        if (comp) {
            file.write(reinterpret_cast<const char*>(&comp->mass), sizeof(comp->mass));
            file.write(reinterpret_cast<const char*>(comp->velocity), sizeof(comp->velocity));
            file.write(reinterpret_cast<const char*>(comp->angularVelocity), sizeof(comp->angularVelocity));
            file.write(reinterpret_cast<const char*>(comp->force), sizeof(comp->force));
            file.write(reinterpret_cast<const char*>(comp->torque), sizeof(comp->torque));
            file.write(reinterpret_cast<const char*>(&comp->useGravity), sizeof(comp->useGravity));
            file.write(reinterpret_cast<const char*>(&comp->isKinematic), sizeof(comp->isKinematic));
            file.write(reinterpret_cast<const char*>(&comp->drag), sizeof(comp->drag));
            file.write(reinterpret_cast<const char*>(&comp->angularDrag), sizeof(comp->angularDrag));
        }
    } else if (type == typeid(ColliderComponent)) {
        auto* comp = scene.componentManager.getComponent<ColliderComponent>(entity);
        if (comp) {
            uint8_t typeVal = static_cast<uint8_t>(comp->type);
            file.write(reinterpret_cast<const char*>(&typeVal), sizeof(typeVal));
            file.write(reinterpret_cast<const char*>(comp->center), sizeof(comp->center));
            file.write(reinterpret_cast<const char*>(comp->size), sizeof(comp->size));
            file.write(reinterpret_cast<const char*>(&comp->isTrigger), sizeof(comp->isTrigger));
            file.write(reinterpret_cast<const char*>(&comp->friction), sizeof(comp->friction));
            file.write(reinterpret_cast<const char*>(&comp->restitution), sizeof(comp->restitution));
            file.write(reinterpret_cast<const char*>(&comp->layer), sizeof(comp->layer));
            file.write(reinterpret_cast<const char*>(&comp->mask), sizeof(comp->mask));
        }
    } else if (type == typeid(AudioSourceComponent)) {
        auto* comp = scene.componentManager.getComponent<AudioSourceComponent>(entity);
        if (comp) {
            file.write(reinterpret_cast<const char*>(&comp->clipID), sizeof(comp->clipID));
            file.write(reinterpret_cast<const char*>(&comp->volume), sizeof(comp->volume));
            file.write(reinterpret_cast<const char*>(&comp->pitch), sizeof(comp->pitch));
            file.write(reinterpret_cast<const char*>(&comp->loop), sizeof(comp->loop));
            file.write(reinterpret_cast<const char*>(&comp->playOnAwake), sizeof(comp->playOnAwake));
            file.write(reinterpret_cast<const char*>(&comp->spatial), sizeof(comp->spatial));
            file.write(reinterpret_cast<const char*>(&comp->minDistance), sizeof(comp->minDistance));
            file.write(reinterpret_cast<const char*>(&comp->maxDistance), sizeof(comp->maxDistance));
            file.write(reinterpret_cast<const char*>(&comp->playing), sizeof(comp->playing));
        }
    } else if (type == typeid(ScriptComponent)) {
        auto* comp = scene.componentManager.getComponent<ScriptComponent>(entity);
        if (comp) {
            uint32_t pathLen = static_cast<uint32_t>(std::strlen(comp->scriptPath));
            file.write(reinterpret_cast<const char*>(&pathLen), sizeof(pathLen));
            file.write(comp->scriptPath, pathLen);
            file.write(reinterpret_cast<const char*>(&comp->scriptInstanceID), sizeof(comp->scriptInstanceID));
            file.write(reinterpret_cast<const char*>(&comp->enabled), sizeof(comp->enabled));
        }
    } else if (type == typeid(PrefabComponent)) {
        auto* comp = scene.componentManager.getComponent<PrefabComponent>(entity);
        if (comp) {
            file.write(reinterpret_cast<const char*>(&comp->prefabID), sizeof(comp->prefabID));
            file.write(reinterpret_cast<const char*>(&comp->instanceID), sizeof(comp->instanceID));
            file.write(reinterpret_cast<const char*>(&comp->isPrefabRoot), sizeof(comp->isPrefabRoot));
            file.write(reinterpret_cast<const char*>(&comp->modified), sizeof(comp->modified));
        }
    } else if (type == typeid(MaterialComponent)) {
        auto* comp = scene.componentManager.getComponent<MaterialComponent>(entity);
        if (comp) {
            uint32_t propCount = static_cast<uint32_t>(comp->floatProperties.size());
            file.write(reinterpret_cast<const char*>(&propCount), sizeof(propCount));
            for (const auto& [key, value] : comp->floatProperties) {
                uint32_t keyLen = static_cast<uint32_t>(key.size());
                file.write(reinterpret_cast<const char*>(&keyLen), sizeof(keyLen));
                file.write(key.c_str(), keyLen);
                file.write(reinterpret_cast<const char*>(&value), sizeof(value));
            }
        }
    } else if (type == typeid(MeshComponent)) {
        auto* comp = scene.componentManager.getComponent<MeshComponent>(entity);
        if (comp) {
            file.write(reinterpret_cast<const char*>(&comp->meshAssetID), sizeof(comp->meshAssetID));
            uint32_t indexCount = static_cast<uint32_t>(comp->indices.size());
            file.write(reinterpret_cast<const char*>(&indexCount), sizeof(indexCount));
            file.write(reinterpret_cast<const char*>(comp->indices.data()), indexCount * sizeof(uint32_t));
            file.write(reinterpret_cast<const char*>(comp->localBounds), sizeof(comp->localBounds));
        }
    } else if (type == typeid(AnimationComponent)) {
        auto* comp = scene.componentManager.getComponent<AnimationComponent>(entity);
        if (comp) {
            file.write(reinterpret_cast<const char*>(&comp->clipID), sizeof(comp->clipID));
            file.write(reinterpret_cast<const char*>(&comp->speed), sizeof(comp->speed));
            file.write(reinterpret_cast<const char*>(&comp->weight), sizeof(comp->weight));
            file.write(reinterpret_cast<const char*>(&comp->normalizedTime), sizeof(comp->normalizedTime));
            file.write(reinterpret_cast<const char*>(&comp->playing), sizeof(comp->playing));
            file.write(reinterpret_cast<const char*>(&comp->loop), sizeof(comp->loop));
        }
    } else if (type == typeid(UIElementComponent)) {
        auto* comp = scene.componentManager.getComponent<UIElementComponent>(entity);
        if (comp) {
            uint8_t typeVal = static_cast<uint8_t>(comp->type);
            file.write(reinterpret_cast<const char*>(&typeVal), sizeof(typeVal));
            file.write(reinterpret_cast<const char*>(comp->rect), sizeof(comp->rect));
            file.write(reinterpret_cast<const char*>(comp->anchorMin), sizeof(comp->anchorMin));
            file.write(reinterpret_cast<const char*>(comp->anchorMax), sizeof(comp->anchorMax));
            file.write(reinterpret_cast<const char*>(comp->pivot), sizeof(comp->pivot));
            file.write(reinterpret_cast<const char*>(comp->color), sizeof(comp->color));
            uint32_t textLen = static_cast<uint32_t>(std::strlen(comp->text));
            file.write(reinterpret_cast<const char*>(&textLen), sizeof(textLen));
            file.write(comp->text, textLen);
            file.write(reinterpret_cast<const char*>(&comp->fontSize), sizeof(comp->fontSize));
            file.write(reinterpret_cast<const char*>(&comp->fontID), sizeof(comp->fontID));
            file.write(reinterpret_cast<const char*>(&comp->fontStyle), sizeof(comp->fontStyle));
            file.write(reinterpret_cast<const char*>(&comp->alignment), sizeof(comp->alignment));
            file.write(reinterpret_cast<const char*>(&comp->raycastTarget), sizeof(comp->raycastTarget));
            file.write(reinterpret_cast<const char*>(&comp->interactable), sizeof(comp->interactable));
            file.write(reinterpret_cast<const char*>(&comp->alpha), sizeof(comp->alpha));
        }
    } else if (type == typeid(CanvasComponent)) {
        auto* comp = scene.componentManager.getComponent<CanvasComponent>(entity);
        if (comp) {
            file.write(reinterpret_cast<const char*>(&comp->scaleFactor), sizeof(comp->scaleFactor));
            file.write(reinterpret_cast<const char*>(&comp->pixelPerfect), sizeof(comp->pixelPerfect));
            file.write(reinterpret_cast<const char*>(comp->referenceResolution), sizeof(comp->referenceResolution));
            uint8_t scaleModeVal = static_cast<uint8_t>(comp->scaleMode);
            file.write(reinterpret_cast<const char*>(&scaleModeVal), sizeof(scaleModeVal));
            file.write(reinterpret_cast<const char*>(&comp->matchWidthOrHeight), sizeof(comp->matchWidthOrHeight));
            file.write(reinterpret_cast<const char*>(&comp->referencePixelsPerUnit), sizeof(comp->referencePixelsPerUnit));
        }
    } else if (type == typeid(ParticleSystemComponent)) {
        auto* comp = scene.componentManager.getComponent<ParticleSystemComponent>(entity);
        if (comp) {
            file.write(reinterpret_cast<const char*>(&comp->duration), sizeof(comp->duration));
            file.write(reinterpret_cast<const char*>(&comp->loop), sizeof(comp->loop));
            file.write(reinterpret_cast<const char*>(&comp->startLifetime), sizeof(comp->startLifetime));
            file.write(reinterpret_cast<const char*>(&comp->startSpeed), sizeof(comp->startSpeed));
            file.write(reinterpret_cast<const char*>(&comp->startSize), sizeof(comp->startSize));
            file.write(reinterpret_cast<const char*>(comp->startColor), sizeof(comp->startColor));
            file.write(reinterpret_cast<const char*>(&comp->gravityModifier), sizeof(comp->gravityModifier));
            file.write(reinterpret_cast<const char*>(&comp->maxParticles), sizeof(comp->maxParticles));
            file.write(reinterpret_cast<const char*>(&comp->emissionRate), sizeof(comp->emissionRate));
            file.write(reinterpret_cast<const char*>(comp->startSize3D), sizeof(comp->startSize3D));
            file.write(reinterpret_cast<const char*>(comp->startRotation), sizeof(comp->startRotation));
            file.write(reinterpret_cast<const char*>(comp->gravityModifier3D), sizeof(comp->gravityModifier3D));
        }
    } else if (type == typeid(NavMeshAgentComponent)) {
        auto* comp = scene.componentManager.getComponent<NavMeshAgentComponent>(entity);
        if (comp) {
            file.write(reinterpret_cast<const char*>(&comp->speed), sizeof(comp->speed));
            file.write(reinterpret_cast<const char*>(&comp->angularSpeed), sizeof(comp->angularSpeed));
            file.write(reinterpret_cast<const char*>(&comp->acceleration), sizeof(comp->acceleration));
            file.write(reinterpret_cast<const char*>(&comp->stoppingDistance), sizeof(comp->stoppingDistance));
            file.write(reinterpret_cast<const char*>(&comp->radius), sizeof(comp->radius));
            file.write(reinterpret_cast<const char*>(&comp->height), sizeof(comp->height));
            file.write(reinterpret_cast<const char*>(&comp->areaMask), sizeof(comp->areaMask));
            file.write(reinterpret_cast<const char*>(comp->destination), sizeof(comp->destination));
            file.write(reinterpret_cast<const char*>(&comp->hasPath), sizeof(comp->hasPath));
            file.write(reinterpret_cast<const char*>(&comp->pathPending), sizeof(comp->pathPending));
        }
    } else if (type == typeid(AnimationComponent)) {
        // Already handled above
    } else {
        // Unknown component type - skip
    }
}

void SceneSerializer::deserializeEntity(std::ifstream& file, Scene& scene, EntityID& parentEntity) {
    EntityID entity = 0;
    file.read(reinterpret_cast<char*>(&entity), sizeof(entity));

    // Read name
    uint32_t nameLen = 0;
    file.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
    std::string name(nameLen, '\0');
    file.read(&name[0], nameLen);

    // Create entity
    entity = scene.entityManager.createEntity(name);

    // Read parent
    file.read(reinterpret_cast<char*>(&parentEntity), sizeof(parentEntity));
    if (parentEntity != INVALID_ENTITY) {
        scene.entityManager.setParent(entity, parentEntity);
    }

    // Read active state
    bool active = false;
    file.read(reinterpret_cast<const char*>(&active), sizeof(active));
    scene.entityManager.setActive(entity, active);

    // Read components
    uint32_t componentCount = 0;
    file.read(reinterpret_cast<char*>(&componentCount), sizeof(componentCount));
    for (uint32_t i = 0; i < componentCount; ++i) {
        uint32_t typeLen = 0;
        file.read(reinterpret_cast<char*>(&typeLen), sizeof(typeLen));
        std::string typeName(typeLen, '\0');
        file.read(&typeName[0], typeLen);
        deserializeComponent(file, entity, typeName, scene);
    }

    // Read children
    uint32_t childCount = 0;
    file.read(reinterpret_cast<char*>(&childCount), sizeof(childCount));
    for (uint32_t i = 0; i < childCount; ++i) {
        deserializeEntity(file, scene, entity);
    }
}

void SceneSerializer::deserializeComponent(std::ifstream& file, EntityID entity, const std::string& typeName, Scene& scene) {
    if (typeName.find("TransformComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<TransformComponent>(entity);
        file.read(reinterpret_cast<char*>(comp->position), sizeof(comp->position));
        file.read(reinterpret_cast<char*>(comp->rotation), sizeof(comp->rotation));
        file.read(reinterpret_cast<char*>(comp->scale), sizeof(comp->scale));
        file.read(reinterpret_cast<char*>(&comp->dirty), sizeof(comp->dirty));
    } else if (typeName.find("NameComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<NameComponent>(entity);
        uint32_t nameLen = 0;
        file.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
        file.read(comp->name, nameLen);
        comp->name[nameLen] = '\0';
    } else if (typeName.find("TagComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<TagComponent>(entity);
        uint32_t tagLen = 0;
        file.read(reinterpret_cast<char*>(&tagLen), sizeof(tagLen));
        file.read(comp->tag, tagLen);
        comp->tag[tagLen] = '\0';
    } else if (typeName.find("MeshRendererComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<MeshRendererComponent>(entity);
        file.read(reinterpret_cast<char*>(&comp->meshID), sizeof(comp->meshID));
        file.read(reinterpret_cast<const char*>(&comp->materialID), sizeof(comp->materialID));
        file.read(reinterpret_cast<char*>(&comp->visible), sizeof(comp->visible));
        file.read(reinterpret_cast<const char*>(&comp->castShadows), sizeof(comp->castShadows));
        file.read(reinterpret_cast<const char*>(&comp->receiveShadows), sizeof(comp->receiveShadows));
    } else if (typeName.find("CameraComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<CameraComponent>(entity);
        file.read(reinterpret_cast<const char*>(&comp->fov), sizeof(comp->fov));
        file.read(reinterpret_cast<const char*>(&comp->nearPlane), sizeof(comp->nearPlane));
        file.read(reinterpret_cast<const char*>(&comp->farPlane), sizeof(comp->farPlane));
        file.read(reinterpret_cast<const char*>(&comp->aspectRatio), sizeof(comp->aspectRatio));
        file.read(reinterpret_cast<const char*>(&comp->isMain), sizeof(comp->isMain));
        file.read(reinterpret_cast<const char*>(&comp->orthographic), sizeof(comp->orthographic));
        file.read(reinterpret_cast<const char*>(&comp->orthoSize), sizeof(comp->orthoSize));
    } else if (typeName.find("LightComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<LightComponent>(entity);
        uint8_t typeVal = 0;
        file.read(reinterpret_cast<char*>(&typeVal), sizeof(typeVal));
        comp->type = static_cast<LightComponent::Type>(typeVal);
        file.read(reinterpret_cast<const char*>(comp->color), sizeof(comp->color));
        file.read(reinterpret_cast<const char*>(&comp->intensity), sizeof(comp->intensity));
        file.read(reinterpret_cast<const char*>(&comp->range), sizeof(comp->range));
        file.read(reinterpret_cast<const char*>(&comp->spotAngle), sizeof(comp->spotAngle));
        file.read(reinterpret_cast<const char*>(&comp->innerAngle), sizeof(comp->innerAngle));
        file.read(reinterpret_cast<const char*>(&comp->castShadows), sizeof(comp->castShadows));
        file.read(reinterpret_cast<const char*>(&comp->shadowBias), sizeof(comp->shadowBias));
    } else if (typeName.find("RigidBodyComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<RigidBodyComponent>(entity);
        file.read(reinterpret_cast<const char*>(&comp->mass), sizeof(comp->mass));
        file.read(reinterpret_cast<const char*>(comp->velocity), sizeof(comp->velocity));
        file.read(reinterpret_cast<const char*>(comp->angularVelocity), sizeof(comp->angularVelocity));
        file.read(reinterpret_cast<const char*>(comp->force), sizeof(comp->force));
        file.read(reinterpret_cast<const char*>(comp->torque), sizeof(comp->torque));
        file.read(reinterpret_cast<const char*>(&comp->useGravity), sizeof(comp->useGravity));
        file.read(reinterpret_cast<const char*>(&comp->isKinematic), sizeof(comp->isKinematic));
        file.read(reinterpret_cast<const char*>(&comp->drag), sizeof(comp->drag));
        file.read(reinterpret_cast<const char*>(&comp->angularDrag), sizeof(comp->angularDrag));
    } else if (typeName.find("ColliderComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<ColliderComponent>(entity);
        uint8_t typeVal = 0;
        file.read(reinterpret_cast<char*>(&typeVal), sizeof(typeVal));
        comp->type = static_cast<ColliderComponent::Type>(typeVal);
        file.read(reinterpret_cast<const char*>(comp->center), sizeof(comp->center));
        file.read(reinterpret_cast<const char*>(comp->size), sizeof(comp->size));
        file.read(reinterpret_cast<const char*>(&comp->isTrigger), sizeof(comp->isTrigger));
        file.read(reinterpret_cast<const char*>(&comp->friction), sizeof(comp->friction));
        file.read(reinterpret_cast<const char*>(&comp->restitution), sizeof(comp->restitution));
        file.read(reinterpret_cast<const char*>(&comp->layer), sizeof(comp->layer));
        file.read(reinterpret_cast<const char*>(&comp->mask), sizeof(comp->mask));
    } else if (typeName.find("AudioSourceComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<AudioSourceComponent>(entity);
        file.read(reinterpret_cast<const char*>(&comp->clipID), sizeof(comp->clipID));
        file.read(reinterpret_cast<const char*>(&comp->volume), sizeof(comp->volume));
        file.read(reinterpret_cast<const char*>(&comp->pitch), sizeof(comp->pitch));
        file.read(reinterpret_cast<const char*>(&comp->loop), sizeof(comp->loop));
        file.read(reinterpret_cast<const char*>(&comp->playOnAwake), sizeof(comp->playOnAwake));
        file.read(reinterpret_cast<const char*>(&comp->spatial), sizeof(comp->spatial));
        file.read(reinterpret_cast<const char*>(&comp->minDistance), sizeof(comp->minDistance));
        file.read(reinterpret_cast<const char*>(&comp->maxDistance), sizeof(comp->maxDistance));
        file.read(reinterpret_cast<const char*>(&comp->playing), sizeof(comp->playing));
    } else if (typeName.find("ScriptComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<ScriptComponent>(entity);
        uint32_t pathLen = 0;
        file.read(reinterpret_cast<char*>(&pathLen), sizeof(pathLen));
        file.read(comp->scriptPath, pathLen);
        comp->scriptPath[pathLen] = '\0';
        file.read(reinterpret_cast<const char*>(&comp->scriptInstanceID), sizeof(comp->scriptInstanceID));
        file.read(reinterpret_cast<const char*>(&comp->enabled), sizeof(comp->enabled));
    } else if (typeName.find("PrefabComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<PrefabComponent>(entity);
        file.read(reinterpret_cast<const char*>(&comp->prefabID), sizeof(comp->prefabID));
        file.read(reinterpret_cast<const char*>(&comp->instanceID), sizeof(comp->instanceID));
        file.read(reinterpret_cast<const char*>(&comp->isPrefabRoot), sizeof(comp->isPrefabRoot));
        file.read(reinterpret_cast<const char*>(&comp->modified), sizeof(comp->modified));
    } else if (typeName.find("MaterialComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<MaterialComponent>(entity);
        uint32_t propCount = 0;
        file.read(reinterpret_cast<const char*>(&propCount), sizeof(propCount));
        for (uint32_t i = 0; i < propCount; ++i) {
            uint32_t keyLen = 0;
            file.read(reinterpret_cast<char*>(&keyLen), sizeof(keyLen));
            std::string key(keyLen, '\0');
            file.read(&key[0], keyLen);
            float value = 0.0f;
            file.read(reinterpret_cast<const char*>(&value), sizeof(value));
            comp->floatProperties[key] = value;
        }
    } else if (typeName.find("MeshComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<MeshComponent>(entity);
        file.read(reinterpret_cast<const char*>(&comp->meshAssetID), sizeof(comp->meshAssetID));
        uint32_t indexCount = 0;
        file.read(reinterpret_cast<const char*>(&indexCount), sizeof(indexCount));
        comp->indices.resize(indexCount);
        file.read(reinterpret_cast<const char*>(comp->indices.data()), indexCount * sizeof(uint32_t));
        file.read(reinterpret_cast<const char*>(comp->localBounds), sizeof(comp->localBounds));
    } else if (typeName.find("AnimationComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<AnimationComponent>(entity);
        file.read(reinterpret_cast<const char*>(&comp->clipID), sizeof(comp->clipID));
        file.read(reinterpret_cast<const char*>(&comp->speed), sizeof(comp->speed));
        file.read(reinterpret_cast<const char*>(&comp->weight), sizeof(comp->weight));
        file.read(reinterpret_cast<const char*>(&comp->normalizedTime), sizeof(comp->normalizedTime));
        file.read(reinterpret_cast<const char*>(&comp->playing), sizeof(comp->playing));
        file.read(reinterpret_cast<const char*>(&comp->loop), sizeof(comp->loop));
    } else if (typeName.find("UIElementComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<UIElementComponent>(entity);
        uint8_t typeVal = 0;
        file.read(reinterpret_cast<char*>(&typeVal), sizeof(typeVal));
        comp->type = static_cast<UIElementComponent::Type>(typeVal);
        file.read(reinterpret_cast<const char*>(comp->rect), sizeof(comp->rect));
        file.read(reinterpret_cast<const char*>(comp->anchorMin), sizeof(comp->anchorMin));
        file.read(reinterpret_cast<const char*>(comp->anchorMax), sizeof(comp->anchorMax));
        file.read(reinterpret_cast<const char*>(comp->pivot), sizeof(comp->pivot));
        file.read(reinterpret_cast<const char*>(comp->color), sizeof(comp->color));
        uint32_t textLen = 0;
        file.read(reinterpret_cast<const char*>(&textLen), sizeof(textLen));
        file.read(comp->text, textLen);
        comp->text[textLen] = '\0';
        file.read(reinterpret_cast<const char*>(&comp->fontSize), sizeof(comp->fontSize));
        file.read(reinterpret_cast<const char*>(&comp->fontID), sizeof(comp->fontID));
        file.read(reinterpret_cast<const char*>(&comp->fontStyle), sizeof(comp->fontStyle));
        file.read(reinterpret_cast<const char*>(&comp->alignment), sizeof(comp->alignment));
        file.read(reinterpret_cast<const char*>(&comp->raycastTarget), sizeof(comp->raycastTarget));
        file.read(reinterpret_cast<const char*>(&comp->interactable), sizeof(comp->interactable));
        file.read(reinterpret_cast<const char*>(&comp->alpha), sizeof(comp->alpha));
    } else if (typeName.find("CanvasComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<CanvasComponent>(entity);
        file.read(reinterpret_cast<const char*>(&comp->scaleFactor), sizeof(comp->scaleFactor));
        file.read(reinterpret_cast<const char*>(&comp->pixelPerfect), sizeof(comp->pixelPerfect));
        file.read(reinterpret_cast<const char*>(comp->referenceResolution), sizeof(comp->referenceResolution));
        uint8_t scaleModeVal = 0;
        file.read(reinterpret_cast<char*>(&scaleModeVal), sizeof(scaleModeVal));
        comp->scaleMode = static_cast<CanvasComponent::ScaleMode>(scaleModeVal);
        file.read(reinterpret_cast<const char*>(&comp->matchWidthOrHeight), sizeof(comp->matchWidthOrHeight));
        file.read(reinterpret_cast<const char*>(&comp->referencePixelsPerUnit), sizeof(comp->referencePixelsPerUnit));
    } else if (typeName.find("ParticleSystemComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<ParticleSystemComponent>(entity);
        file.read(reinterpret_cast<const char*>(&comp->duration), sizeof(comp->duration));
        file.read(reinterpret_cast<const char*>(&comp->loop), sizeof(comp->loop));
        file.read(reinterpret_cast<const char*>(&comp->startLifetime), sizeof(comp->startLifetime));
        file.read(reinterpret_cast<const char*>(&comp->startSpeed), sizeof(comp->startSpeed));
        file.read(reinterpret_cast<const char*>(&comp->startSize), sizeof(comp->startSize));
        file.read(reinterpret_cast<const char*>(comp->startColor), sizeof(comp->startColor));
        file.read(reinterpret_cast<const char*>(&comp->gravityModifier), sizeof(comp->gravityModifier));
        file.read(reinterpret_cast<const char*>(&comp->maxParticles), sizeof(comp->maxParticles));
        file.read(reinterpret_cast<const char*>(&comp->emissionRate), sizeof(comp->emissionRate));
        file.read(reinterpret_cast<const char*>(comp->startSize3D), sizeof(comp->startSize3D));
        file.read(reinterpret_cast<const char*>(comp->startRotation), sizeof(comp->startRotation));
        file.read(reinterpret_cast<const char*>(comp->gravityModifier3D), sizeof(comp->gravityModifier3D));
    } else if (typeName.find("NavMeshAgentComponent") != std::string::npos) {
        auto* comp = scene.componentManager.addComponent<NavMeshAgentComponent>(entity);
        file.read(reinterpret_cast<const char*>(&comp->speed), sizeof(comp->speed));
        file.read(reinterpret_cast<const char*>(&comp->angularSpeed), sizeof(comp->angularSpeed));
        file.read(reinterpret_cast<const char*>(&comp->acceleration), sizeof(comp->acceleration));
        file.read(reinterpret_cast<const char*>(&comp->stoppingDistance), sizeof(comp->stoppingDistance));
        file.read(reinterpret_cast<const char*>(&comp->radius), sizeof(comp->radius));
        file.read(reinterpret_cast<const char*>(&comp->height), sizeof(comp->height));
        file.read(reinterpret_cast<const char*>(&comp->areaMask), sizeof(comp->areaMask));
        file.read(reinterpret_cast<const char*>(comp->destination), sizeof(comp->destination));
        file.read(reinterpret_cast<const char*>(&comp->hasPath), sizeof(comp->hasPath));
        file.read(reinterpret_cast<const char*>(&comp->pathPending), sizeof(comp->pathPending));
    }
    // Unknown component types are skipped
}

std::string SceneSerializer::vec3ToString(const glm::vec3& v) {
    return std::to_string(v.x) + "," + std::to_string(v.y) + "," + std::to_string(v.z);
}

glm::vec3 SceneSerializer::stringToVec3(const std::string& s) {
    glm::vec3 v = {0, 0, 0};
    std::istringstream iss(s);
    char comma;
    iss >> v.x >> comma >> v.y >> comma >> v.z;
    return v;
}

std::string SceneSerializer::quatToString(const glm::quat& q) {
    return std::to_string(q.w) + "," + std::to_string(q.x) + "," + std::to_string(q.y) + "," + std::to_string(q.z);
}

glm::quat SceneSerializer::stringToQuat(const std::string& s) {
    glm::quat q = {1, 0, 0, 0};
    std::istringstream iss(s);
    char comma;
    iss >> q.w >> comma >> q.x >> comma >> q.y >> comma >> q.z;
    return q;
}

std::string SceneSerializer::mat4ToString(const glm::mat4& m) {
    std::string result;
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            result += std::to_string(m[i][j]);
            if (i < 3 || j < 3) result += ",";
        }
    }
    return result;
}

glm::mat4 SceneSerializer::stringToMat4(const std::string& s) {
    glm::mat4 m(1.0f);
    std::istringstream iss(s);
    char comma;
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            iss >> m[i][j] >> comma;
        }
    }
    return m;
}

} // namespace kartgib::editor