#include "HybridScene.hpp"

#include <cmath>

namespace sunshine {
namespace {

bool overlap(const Aabb& a, const Aabb& b) {
    if (!a.valid || !b.valid) return false;
    return a.mn.x <= b.mx.x && a.mx.x >= b.mn.x &&
           a.mn.y <= b.mx.y && a.mx.y >= b.mn.y &&
           a.mn.z <= b.mx.z && a.mx.z >= b.mn.z;
}

}  // namespace

bool HybridScene::move(uint64_t id, Vec3f translation) {
    SceneEntity* entity = mutableFind(id);
    if (entity == nullptr) return false;
    entity->translation = translation;
    return true;
}

bool HybridScene::setPose(uint64_t id, Vec3f poseRoot) {
    SceneEntity* entity = mutableFind(id);
    if (entity == nullptr || entity->kind != GeometryKind::SkeletalMesh) return false;
    entity->poseRoot = poseRoot;
    return true;
}

void HybridScene::setLight(const LightRecord& light) { light_ = light; }

void HybridScene::addMaterial(const MaterialRecord& material) {
    for (MaterialRecord& slot : materials_) {
        if (slot.id == material.id) {
            slot = material;
            return;
        }
    }
    materials_.push_back(material);
}

const MaterialRecord* HybridScene::material(uint32_t id) const {
    for (const MaterialRecord& slot : materials_) {
        if (slot.id == id) return &slot;
    }
    return nullptr;
}

Aabb HybridScene::bounds(uint64_t id) const {
    Aabb box;
    const SceneEntity* entity = find(id);
    if (entity == nullptr) return box;
    if (entity->kind == GeometryKind::StaticMesh && !entity->vertices.empty()) {
        box.mn = entity->vertices[0];
        box.mx = entity->vertices[0];
        for (const Vec3f& vertex : entity->vertices) {
            box.mn.x = vertex.x < box.mn.x ? vertex.x : box.mn.x;
            box.mn.y = vertex.y < box.mn.y ? vertex.y : box.mn.y;
            box.mn.z = vertex.z < box.mn.z ? vertex.z : box.mn.z;
            box.mx.x = vertex.x > box.mx.x ? vertex.x : box.mx.x;
            box.mx.y = vertex.y > box.mx.y ? vertex.y : box.mx.y;
            box.mx.z = vertex.z > box.mx.z ? vertex.z : box.mx.z;
        }
        box.mn.x += entity->translation.x;
        box.mn.y += entity->translation.y;
        box.mn.z += entity->translation.z;
        box.mx.x += entity->translation.x;
        box.mx.y += entity->translation.y;
        box.mx.z += entity->translation.z;
        box.valid = true;
        return box;
    }
    if (entity->kind == GeometryKind::SkeletalMesh) {
        constexpr float radius = 0.35f;
        constexpr float height = 1.8f;
        box.mn = {entity->translation.x - radius, entity->translation.y, entity->translation.z - radius};
        box.mx = {entity->translation.x + radius, entity->translation.y + height, entity->translation.z + radius};
        box.valid = true;
    }
    return box;
}

bool HybridScene::contacts(uint64_t a, uint64_t b) const {
    return overlap(bounds(a), bounds(b));
}

bool HybridScene::supportedByTerrain(uint64_t id) const {
    const SceneEntity* entity = find(id);
    if (entity == nullptr || entity->kind != GeometryKind::SkeletalMesh) return false;
    const int32_t x = static_cast<int32_t>(std::floor(entity->translation.x));
    const int32_t z = static_cast<int32_t>(std::floor(entity->translation.z));
    const float ground = static_cast<float>(world_.terrainHeight(x, z)) + 1.0f;
    return std::fabs(entity->translation.y - ground) <= 0.05f;
}

}  // namespace sunshine
