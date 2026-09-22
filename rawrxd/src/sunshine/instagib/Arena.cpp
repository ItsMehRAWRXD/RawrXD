#include "Arena.hpp"

namespace Sunshine {

void Arena::addBox(const Vec3& min_, const Vec3& max_) {
    AABB b;
    b.min = min_;
    b.max = max_;
    boxes.push_back(b);
}

void Arena::addSpawn(const Vec3& pos, float yaw) {
    spawns.push_back({pos, yaw});
}

bool Arena::findSpawn(int index, Vec3* outPos, float* outYaw) const {
    if (index < 0 || index >= (int)spawns.size()) return false;
    if (outPos) *outPos = spawns[index].pos;
    if (outYaw) *outYaw = spawns[index].yaw;
    return true;
}

} // namespace Sunshine
