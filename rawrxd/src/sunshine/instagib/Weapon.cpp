#include "Weapon.hpp"

namespace Sunshine {

bool Weapon::raycast(const Vec3& origin, const Vec3& dir,
                     const AABB* boxes, int boxCount,
                     const Sphere* spheres, int sphereCount,
                     Vec3* outHitPos, int* outHitId) {
    float closestT = range;
    bool hit = false;
    int hitId = -1;

    Ray ray;
    ray.origin = origin;
    ray.dir = dir;

    for (int i = 0; i < boxCount; ++i) {
        float t = 0.0f;
        if (ray.intersectsAABB(boxes[i], &t)) {
            if (t < closestT) {
                closestT = t;
                hit = true;
                hitId = i;
            }
        }
    }

    for (int i = 0; i < sphereCount; ++i) {
        float t = 0.0f;
        if (ray.intersectsSphere(spheres[i], &t)) {
            if (t < closestT) {
                closestT = t;
                hit = true;
                hitId = boxCount + i;
            }
        }
    }

    if (hit && outHitPos) {
        *outHitPos = origin + dir * closestT;
    }
    if (outHitId) {
        *outHitId = hitId;
    }
    return hit;
}

} // namespace Sunshine
