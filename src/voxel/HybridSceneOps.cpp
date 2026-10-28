#include "HybridScene.hpp"

#include <cmath>
#include <cstring>

namespace sunshine {
namespace {

void copyName(char* dst, const char* src) {
    std::memset(dst, 0, 32);
    if (src == nullptr) return;
    for (int i = 0; i < 31 && src[i] != '\0'; ++i) dst[i] = src[i];
}

}  // namespace

HybridScene::HybridScene(uint32_t seed) : world_(seed) {}

SceneEntity* HybridScene::mutableFind(uint64_t id) {
    for (auto& entity : entities_) if (entity.id == id) return &entity;
    return nullptr;
}

const SceneEntity* HybridScene::find(uint64_t id) const {
    for (const auto& entity : entities_) {
        if (entity.id == id) return &entity;
    }
    return nullptr;
}

uint64_t HybridScene::push(SceneEntity entity) {
    entity.id = next_++;
    entities_.push_back(std::move(entity));
    return entities_.back().id;
}

uint64_t HybridScene::addVoxel(const char* name, uint32_t materialId) {
    SceneEntity entity;
    entity.kind = GeometryKind::VoxelVolume;
    entity.materialId = materialId;
    copyName(entity.name, name);
    return push(std::move(entity));
}

uint64_t HybridScene::addMesh(const char* name, uint32_t materialId,
                              const std::vector<Vec3f>& vertices,
                              const std::vector<uint32_t>& indices, Vec3f translation) {
    SceneEntity entity;
    entity.kind = GeometryKind::StaticMesh;
    entity.materialId = materialId;
    entity.translation = translation;
    entity.vertices = vertices;
    entity.indices = indices;
    copyName(entity.name, name);
    return push(std::move(entity));
}

uint64_t HybridScene::addCharacter(const char* name, uint32_t materialId,
                                   const std::vector<BoneSample>& bones, Vec3f translation) {
    SceneEntity entity;
    entity.kind = GeometryKind::SkeletalMesh;
    entity.materialId = materialId;
    entity.translation = translation;
    entity.bones = bones;
    copyName(entity.name, name);
    return push(std::move(entity));
}

bool HybridScene::setParent(uint64_t id, uint64_t parent) {
    SceneEntity* entity = mutableFind(id);
    if (entity == nullptr || id == parent) return false;
    if (parent != 0 && find(parent) == nullptr) return false;
    for (uint64_t walk = parent; walk != 0;) {
        if (walk == id) return false;
        const SceneEntity* node = find(walk);
        if (node == nullptr) return false;
        walk = node->parent;
    }
    entity->parent = parent;
    return true;
}

bool HybridScene::editVoxel(uint64_t id, int32_t x, int32_t y, int32_t z, uint8_t block) {
    SceneEntity* entity = mutableFind(id);
    if (entity == nullptr || entity->kind != GeometryKind::VoxelVolume) return false;
    if (y < 0 || y >= kChunkHeight) return false;
    const int32_t cx = static_cast<int32_t>(std::floor(static_cast<double>(x) / kChunkSize));
    const int32_t cz = static_cast<int32_t>(std::floor(static_cast<double>(z) / kChunkSize));
    world_.chunk(cx, cz).set(x - cx * kChunkSize, y, z - cz * kChunkSize, block);
    for (VoxelEdit& edit : entity->edits) {
        if (edit.x == x && edit.y == y && edit.z == z) {
            edit.block = block;
            return true;
        }
    }
    entity->edits.push_back(VoxelEdit{x, y, z, block});
    return true;
}
