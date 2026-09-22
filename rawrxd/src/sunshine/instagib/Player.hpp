#pragma once

#include "math.hpp"
#include "Camera.hpp"

namespace Sunshine {

struct Player {
    Camera camera;
    Vec3 spawnPos;
    float yaw = 0.0f;
    float pitch = 0.0f;
    int health = 100;
    int score = 0;
    bool alive = true;
    float respawnTimer = 0.0f;
    float fireCooldown = 0.0f;

    void spawn(const Vec3& pos, float startYaw);
    void takeDamage(int dmg);
    void update(float dt);
    void addScore(int pts);
};

} // namespace Sunshine
