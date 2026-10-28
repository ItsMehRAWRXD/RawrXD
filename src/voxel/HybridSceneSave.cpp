#include "HybridScene.hpp"

#include <cstdio>

namespace sunshine {
namespace {

template <class T>
bool put(FILE* file, const T& value) {
    return std::fwrite(&value, sizeof(T), 1, file) == 1;
}

bool writeEntity(FILE* file, const SceneEntity& entity) {
    const uint8_t kind = static_cast<uint8_t>(entity.kind);
    const uint32_t edits = static_cast<uint32_t>(entity.edits.size());
    const uint32_t verts = static_cast<uint32_t>(entity.vertices.size());
    const uint32_t indices = static_cast<uint32_t>(entity.indices.size());
    const uint32_t bones = static_cast<uint32_t>(entity.bones.size());
    if (!put(file, entity.id) || !put(file, entity.parent) || !put(file, kind) ||
        std::fwrite(entity.name, 1, 32, file) != 32 || !put(file, entity.translation) ||
        !put(file, entity.poseRoot) || !put(file, entity.materialId) || !put(file, edits) ||
        !put(file, verts) || !put(file, indices) || !put(file, bones)) {
        return false;
    }
    for (const VoxelEdit& edit : entity.edits) {
        if (!put(file, edit.x) || !put(file, edit.y) || !put(file, edit.z) || !put(file, edit.block)) {
            return false;
        }
    }
    if (verts != 0 && std::fwrite(entity.vertices.data(), sizeof(Vec3f), verts, file) != verts) return false;
    if (indices != 0 && std::fwrite(entity.indices.data(), sizeof(uint32_t), indices, file) != indices) return false;
    for (const BoneSample& bone : entity.bones) {
        if (!put(file, bone.parent) || !put(file, bone.local)) return false;
    }
    return true;
}

}  // namespace

bool HybridScene::save(const char* path) const {
    FILE* file = std::fopen(path, "wb");
    if (file == nullptr) return false;
    const uint32_t version = 1;
    const uint32_t seed = world_.seed();
    const uint32_t materials = static_cast<uint32_t>(materials_.size());
    const uint32_t entities = static_cast<uint32_t>(entities_.size());
    bool ok = std::fwrite("RHSC", 1, 4, file) == 4 && put(file, version) && put(file, seed) &&
              put(file, light_.dx) && put(file, light_.dy) && put(file, light_.dz) &&
              put(file, light_.intensity) && put(file, light_.r) && put(file, light_.g) &&
              put(file, light_.b) && put(file, materials) && put(file, entities);
    for (uint32_t i = 0; ok && i < materials; ++i) {
        const MaterialRecord& slot = materials_[i];
        ok = put(file, slot.id) && put(file, slot.roughness) && put(file, slot.metallic) &&
             put(file, slot.r) && put(file, slot.g) && put(file, slot.b);
    }
    for (uint32_t i = 0; ok && i < entities; ++i) ok = ok && writeEntity(file, entities_[i]);
    std::fclose(file);
    return ok;
}

}  // namespace sunshine
