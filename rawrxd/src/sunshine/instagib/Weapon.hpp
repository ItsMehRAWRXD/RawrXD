#pragma once

#include "math.hpp"
#include "../core/Primitives.hpp"

namespace Sunshine {

struct Weapon {
    float cooldown = 0.15f;
    int damage = 100; // instagib
    float range = 500.0f;
    float lastFireTime = -999.0f;

    bool canFire(double now) const { return (float)(now - lastFireTime) >= cooldown; }
    void fire(double now) { lastFireTime = (float)now; }

    // Raycast against AABBs and spheres; returns true if hit, writes out hitPos and hitTargetId
    bool raycast(const Vec3& origin, const Vec3& dir,
                 const AABB* boxes, int boxCount,
                 const Sphere* spheres, int sphereCount,
                 Vec3* outHitPos, int* outHitId);
};

} // namespace Sunshine
