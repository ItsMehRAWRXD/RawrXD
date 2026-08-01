#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

// ============================================================================
// Entity Component System — lightweight archetype-based ECS for the engine
// ============================================================================

// ---------------------------------------------------------------------------
// Entity handle
// ---------------------------------------------------------------------------
using Entity = uint32_t;
constexpr Entity INVALID_ENTITY = 0xFFFFFFFF;

// ---------------------------------------------------------------------------
// Component type IDs (compile-time registration)
// ---------------------------------------------------------------------------
using ComponentTypeId = uint32_t;

// ---------------------------------------------------------------------------
// Transform component
// ---------------------------------------------------------------------------
struct TransformComponent {
    float position[3] = {0, 0, 0};
    float rotation[4] = {0, 0, 0, 1}; // quaternion w,x,y,z
    float scale[3] = {1, 1, 1};
};

// ---------------------------------------------------------------------------
// Mesh component
// ---------------------------------------------------------------------------
struct MeshComponent {
    uint64_t vertexBufferHandle = 0;
    uint64_t indexBufferHandle = 0;
    uint32_t vertexCount = 0;
    uint32_t indexCount = 0;
    uint32_t materialId = 0;
};

// ---------------------------------------------------------------------------
// Light component
// ---------------------------------------------------------------------------
struct LightComponent {
    float color[3] = {1, 1, 1};
    float intensity = 1.0f;
    float range = 10.0f;
    uint32_t type = 0; // 0=point, 1=directional, 2=spot
};

// ---------------------------------------------------------------------------
// Tag component (for querying)
// ---------------------------------------------------------------------------
struct TagComponent {
    std::string tag;
};

// ---------------------------------------------------------------------------
// ECS Registry
// ---------------------------------------------------------------------------
class EcsRegistry {
private:
    Entity m_nextEntity = 0;
    std::unordered_map<Entity, TransformComponent> m_transforms;
    std::unordered_map<Entity, MeshComponent>      m_meshes;
    std::unordered_map<Entity, LightComponent>     m_lights;
    std::unordered_map<Entity, TagComponent>       m_tags;
    std::vector<Entity> m_entities;

public:
    Entity CreateEntity() {
        Entity e = m_nextEntity++;
        m_entities.push_back(e);
        m_transforms[e] = TransformComponent{};
        return e;
    }

    void DestroyEntity(Entity e) {
        m_transforms.erase(e);
        m_meshes.erase(e);
        m_lights.erase(e);
        m_tags.erase(e);
    }

    // Component access
    TransformComponent& GetTransform(Entity e) { return m_transforms[e]; }
    MeshComponent&      GetMesh(Entity e)      { return m_meshes[e]; }
    LightComponent&     GetLight(Entity e)     { return m_lights[e]; }
    TagComponent&       GetTag(Entity e)       { return m_tags[e]; }

    bool HasMesh(Entity e) const  { return m_meshes.find(e) != m_meshes.end(); }
    bool HasLight(Entity e) const { return m_lights.find(e) != m_lights.end(); }
    bool HasTag(Entity e) const   { return m_tags.find(e) != m_tags.end(); }

    // Queries
    const std::vector<Entity>& AllEntities() const { return m_entities; }

    std::vector<Entity> QueryByTag(const std::string& tag) const {
        std::vector<Entity> result;
        for (auto& [e, t] : m_tags) {
            if (t.tag == tag) result.push_back(e);
        }
        return result;
    }

    size_t EntityCount() const { return m_entities.size(); }
};
