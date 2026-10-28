#pragma once

#include <cstdint>
#include <vector>

namespace sunshine {

enum class GeometryKind : uint8_t {
    VoxelVolume = 1,
    StaticMesh = 2,
    SkeletalMesh = 3,
};

struct MaterialRecord {
    uint32_t id = 0;
    float roughness = 0.5f;
    float metallic = 0.0f;
    uint8_t r = 0;
    uint8_t g = 0;
    uint8_t b = 0;
};

struct LightRecord {
    float dx = 0.2f;
    float dy = -1.0f;
    float dz = 0.1f;
    float intensity = 1.0f;
    uint8_t r = 255;
    uint8_t g = 244;
    uint8_t b = 214;
};

struct Vec3f {
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
};

struct VoxelEdit {
    int32_t x = 0;
    int32_t y = 0;
    int32_t z = 0;
    uint8_t block = 0;
};

struct BoneSample {
    int32_t parent = -1;
    Vec3f local{};
};

struct SceneEntity {
    uint64_t id = 0;
    uint64_t parent = 0;
    GeometryKind kind = GeometryKind::StaticMesh;
    char name[32]{};
    Vec3f translation{};
    Vec3f poseRoot{};
    uint32_t materialId = 0;
    std::vector<VoxelEdit> edits;
    std::vector<Vec3f> vertices;
    std::vector<uint32_t> indices;
    std::vector<BoneSample> bones;
};

struct Aabb {
    Vec3f mn{};
    Vec3f mx{};
    bool valid = false;
};

}  // namespace sunshine
