#pragma once

#include "ecs.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <filesystem>
#include <optional>
#include <variant>
#include <functional>
#include <chrono>

namespace kartgib::editor {

struct TransformComponent {
    float position[3] = {0, 0, 0};
    float rotation[3] = {0, 0, 0};  // Euler angles in radians
    float scale[3] = {1, 1, 1};

    // Computed world transform (updated by transform system)
    float worldMatrix[16] = {
        1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1
    };
    float localMatrix[16] = {
        1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1
    };
    bool dirty = true;
};

struct NameComponent {
    char name[256] = "Entity";
};

struct TagComponent {
    char tag[64] = "";
};

struct MeshRendererComponent {
    EntityID meshID = INVALID_ENTITY;
    EntityID materialID = INVALID_ENTITY;
    bool visible = true;
    bool castShadows = true;
    bool receiveShadows = true;
};

struct CameraComponent {
    float fov = 60.0f;           // degrees
    float nearPlane = 0.1f;
    float farPlane = 10000.0f;
    float aspectRatio = 16.0f/9.0f;
    bool isMain = false;
    bool orthographic = false;
    float orthoSize = 10.0f;
};

struct LightComponent {
    enum class Type : uint8_t { Directional = 0, Point = 1, Spot = 2 } type = Type::Directional;
    float color[3] = {1, 1, 1};
    float intensity = 1.0f;
    float range = 100.0f;
    float spotAngle = 45.0f;     // degrees
    float innerAngle = 30.0f;    // degrees
    bool castShadows = true;
    float shadowBias = 0.005f;
};

struct RigidBodyComponent {
    float mass = 1.0f;
    float velocity[3] = {0, 0, 0};
    float angularVelocity[3] = {0, 0, 0};
    float force[3] = {0, 0, 0};
    float torque[3] = {0, 0, 0};
    bool useGravity = true;
    bool isKinematic = false;
    float drag = 0.0f;
    float angularDrag = 0.05f;
};

struct ColliderComponent {
    enum class Type : uint8_t { Box = 0, Sphere = 1, Capsule = 3, Mesh = 4 } type = Type::Box;
    float center[3] = {0, 0, 0};
    float size[3] = {1, 1, 1};   // box: half-extents, sphere: radius, capsule: (radius, height)
    bool isTrigger = false;
    float friction = 0.6f;
    float restitution = 0.0f;
    uint32_t layer = 0;
    uint32_t mask = 0xFFFFFFFF;
};

struct AudioSourceComponent {
    EntityID clipID = INVALID_ENTITY;
    float volume = 1.0f;
    float pitch = 1.0f;
    bool loop = false;
    bool playOnAwake = false;
    bool spatial = true;
    float minDistance = 1.0f;
    float maxDistance = 500.0f;
    bool playing = false;
};

struct ScriptComponent {
    char scriptPath[256] = "";
    uint64_t scriptInstanceID = 0;
    bool enabled = true;
};

struct PrefabComponent {
    EntityID prefabID = INVALID_ENTITY;
    EntityID instanceID = INVALID_ENTITY;
    bool isPrefabRoot = false;
    bool modified = false;
};

struct HierarchyComponent {
    EntityID parent = INVALID_ENTITY;
    std::vector<EntityID> children;
    int siblingIndex = 0;
};

struct SceneData {
    std::string name = "Untitled Scene";
    std::string path;
    uint64_t version = 1;
    uint64_t lastModified = 0;
    std::string description;
    EntityID rootEntity = INVALID_ENTITY;
};

struct AssetReference {
    std::string guid;
    std::string path;
    std::string type;
    bool valid = false;
};

struct MaterialComponent {
    EntityID shaderID = INVALID_ENTITY;
    std::vector<std::pair<std::string, AssetReference>> textures;
    std::unordered_map<std::string, float> floats;
    std::unordered_map<std::string, float[4]> vectors;
    std::unordered_map<std::string, AssetReference> textureAssets;
    uint32_t renderQueue = 2000; // opaque
    bool doubleSided = false;
    bool alphaTest = false;
    float alphaCutoff = 0.5f;
};

struct MeshComponent {
    EntityID meshAssetID = INVALID_ENTITY;
    std::vector<uint32_t> subMeshIndices;
    std::vector<AssetReference> materials;
    bool calculateBounds = true;
    float localBounds[6] = {-1,-1,-1, 1,1,1}; // min/max
};

struct AnimationComponent {
    EntityID animatorID = INVALID_ENTITY;
    EntityID currentClipID = INVALID_ENTITY;
    float speed = 1.0f;
    bool playAutomatically = true;
    bool loop = true;
    float normalizedTime = 0.0f;
    bool playing = false;
    float crossfadeDuration = 0.2f;
};

struct AnimationClipComponent {
    std::string name;
    float length = 0.0f;
    float frameRate = 60.0f;
    bool loop = true;
    std::vector<uint64_t> curveBindings; // property paths hashed
    std::vector<float> curvesData; // serialized curves
};

struct AnimatorControllerComponent {
    EntityID controllerAssetID = INVALID_ENTITY;
    std::string currentState;
    float transitionDuration = 0.2f;
    float transitionProgress = 0.0f;
    std::string nextState;
    bool inTransition = false;
};

struct ParticleSystemComponent {
    float duration = 5.0f;
    bool loop = true;
    float startLifetime = 5.0f;
    float startSpeed = 5.0f;
    float startSize = 1.0f;
    float startColor[4] = {1,1,1,1};
    float gravityModifier = 0.0f;
    int maxParticles = 100;
    float emissionRate = 10.0f;
    float startSize3D[3] = {1,1,1};
    float startRotation[2] = {0, 360};
    float gravityModifier3D[3] = {0, -9.81f, 0};
};

struct NavMeshAgentComponent {
    float speed = 3.5f;
    float angularSpeed = 120.0f;
    float acceleration = 8.0f;
    float stoppingDistance = 0.0f;
    float radius = 0.5f;
    float height = 2.0f;
    uint32_t areaMask = 0xFFFFFFFF;
    float destination[3] = {0,0,0};
    bool hasPath = false;
    bool pathPending = false;
};

struct UIElementComponent {
    enum class Type { Panel, Text, Image, Button, InputField, Slider, ScrollView } type = Type::Panel;
    float rect[4] = {0, 0, 100, 100}; // x, y, width, height (0-1 normalized)
    float anchorMin[2] = {0.5f, 0.5f};
    float anchorMax[2] = {0.5f, 0.5f};
    float pivot[2] = {0.5f, 0.5f};
    float color[4] = {1,1,1,1};
    char text[256] = "";
    float fontSize = 14.0f;
    EntityID fontID = INVALID_ENTITY;
    int fontStyle = 0;
    int alignment = 0;
    bool raycastTarget = true;
    bool interactable = true;
    float alpha = 1.0f;
};

struct CanvasComponent {
    float scaleFactor = 1.0f;
    bool pixelPerfect = false;
    float referenceResolution[2] = {1920, 1080};
    enum class ScaleMode { ConstantPixelSize, ScaleWithScreenSize, ConstantPhysicalSize } scaleMode = ScaleMode::ScaleWithScreenSize;
    float matchWidthOrHeight = 0.5f;
    float referencePixelsPerUnit = 100.0f;
};

struct Scene {
    std::string name = "Untitled";
    std::string path;
    uint64_t version = 1;
    EntityID rootEntity = INVALID_ENTITY;
    EntityManager entityManager;
    ComponentManager componentManager;
    std::vector<EntityID> rootEntities;
    std::string name = "Untitled Scene";
    std::string path;
    uint64_t version = 1;
    uint64_t lastModified = 0;
    std::string description;

    Scene() : entityManager(), componentManager(&entityManager) {
        componentManager = ComponentManager(&entityManager);
    }

    EntityID createEntity(const std::string& name = "Entity") {
        EntityID id = entityManager.createEntity(name);
        if (rootEntity == INVALID_ENTITY) {
            rootEntity = id;
            rootEntities.push_back(id);
        }
        return id;
    }

    void destroyEntity(EntityID entity) {
        entityManager.destroyEntity(entity);
        auto it = std::find(rootEntities.begin(), rootEntities.end(), entity);
        if (it != rootEntities.end()) {
            rootEntities.erase(it);
        }
    }

    void setRootEntity(EntityID entity) {
        if (entityManager.isActive(entity)) {
            rootEntity = entity;
            auto it = std::find(rootEntities.begin(), rootEntities.end(), entity);
            if (it == rootEntities.end()) {
                rootEntities.push_back(entity);
            }
        }
    }

    void save(const std::string& path);
    bool load(const std::string& path);
    void clear();
};

} // namespace kartgib::editor