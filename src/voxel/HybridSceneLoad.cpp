#include "HybridScene.hpp"

#include <cstdio>
#include <cstring>

namespace sunshine {
namespace {

template <class T>
bool get(FILE* file, T* value) {
    return std::fread(value, sizeof(T), 1, file) == 1;
}

bool readEntity(FILE* file, SceneEntity* entity) {
    uint8_t kind = 0;
    uint32_t edits = 0;
    uint32_t verts = 0;
    uint32_t indices = 0;
    uint32_t bones = 0;
    if (!get(file, &entity->id) || !get(file, &entity->parent) || !get(file, &kind) ||
        std::fread(entity->name, 1, 32, file) != 32 || !get(file, &entity->translation) ||
        !get(file, &entity->poseRoot) || !get(file, &entity->materialId) || !get(file, &edits) ||
        !get(file, &verts) || !get(file, &indices) || !get(file, &bones)) {
        return false;
    }
    if (kind < 1 || kind > 3 || edits > 100000 || verts > 1000000 || indices > 3000000 || bones > 1024) {
        return false;
    }
    entity->kind = static_cast<GeometryKind>(kind);
    entity->name[31] = '\0';
    entity->edits.resize(edits);
    for (uint32_t i = 0; i < edits; ++i) {
        VoxelEdit& edit = entity->edits[i];
        if (!get(file, &edit.x) || !get(file, &edit.y) || !get(file, &edit.z) || !get(file, &edit.block)) {
            return false;
        }
    }
    entity->vertices.resize(verts);
    entity->indices.resize(indices);
    entity->bones.resize(bones);
    if (verts != 0 && std::fread(entity->vertices.data(), sizeof(Vec3f), verts, file) != verts) return false;
    if (indices != 0 && std::fread(entity->indices.data(), sizeof(uint32_t), indices, file) != indices) return false;
    for (uint32_t i = 0; i < bones; ++i) {
        if (!get(file, &entity->bones[i].parent) || !get(file, &entity->bones[i].local)) return false;
    }
    return true;
}

}  // namespace

bool HybridScene::load(const char* path) {
    FILE* file = std::fopen(path, "rb");
    if (file == nullptr) return false;
    char magic[4]{};
    uint32_t version = 0;
    uint32_t seed = 0;
    LightRecord light;
    uint32_t materialCount = 0;
    uint32_t entityCount = 0;
    bool ok = std::fread(magic, 1, 4, file) == 4 && std::memcmp(magic, "RHSC", 4) == 0 &&
              get(file, &version) && version == 1 && get(file, &seed) && get(file, &light.dx) &&
              get(file, &light.dy) && get(file, &light.dz) && get(file, &light.intensity) &&
              get(file, &light.r) && get(file, &light.g) && get(file, &light.b) &&
              get(file, &materialCount) && get(file, &entityCount) &&
              materialCount <= 4096 && entityCount <= 100000;
    std::vector<MaterialRecord> materials;
    std::vector<SceneEntity> entities;
    if (ok) {
        materials.resize(materialCount);
        entities.resize(entityCount);
    }
    for (uint32_t i = 0; ok && i < materialCount; ++i) {
        MaterialRecord& slot = materials[i];
        ok = get(file, &slot.id) && get(file, &slot.roughness) && get(file, &slot.metallic) &&
             get(file, &slot.r) && get(file, &slot.g) && get(file, &slot.b);
    }
    for (uint32_t i = 0; ok && i < entityCount; ++i) ok = readEntity(file, &entities[i]);
    std::fclose(file);
    if (!ok) return false;
    world_.setSeed(seed);
    light_ = light;
    materials_ = std::move(materials);
    entities_ = std::move(entities);
    next_ = 1;
    for (const SceneEntity& entity : entities_) {
        if (entity.id >= next_) next_ = entity.id + 1;
    }
    applyEdits();
    return true;
}

}  // namespace sunshine
