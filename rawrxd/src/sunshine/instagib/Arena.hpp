#pragma once

#include "math.hpp"
#include "../core/Primitives.hpp"
#include <vector>

namespace Sunshine {

struct SpawnPoint {
    Vec3 pos;
    float yaw;
};

struct Arena {
    std::vector<AABB> boxes;
    std::vector<SpawnPoint> spawns;

    void addBox(const Vec3& min_, const Vec3& max_);
    void addSpawn(const Vec3& pos, float yaw);
    bool findSpawn(int index, Vec3* outPos, float* outYaw) const;
};

} // namespace Sunshine
