#pragma once

#include "Player.hpp"
#include <vector>

namespace Sunshine {

struct Arena;
struct Weapon;

struct Bot {
    Vec3 pos;
    Vec3 spawnPos;
    float yaw = 0.0f;
    int health = 100;
    bool alive = true;
    float respawnTimer = 0.0f;
    float fireCooldown = 0.0f;
    float moveSpeed = 2.0f;
    float turnSpeed = 90.0f; // deg/sec
    float fireRange = 40.0f;
    float thinkTimer = 0.0f;

    void spawn(const Vec3& pos, float startYaw);
    void update(float dt, const Vec3& targetPos, const Arena& arena, double now, Weapon* weapon);
    void takeDamage(int dmg);
    void addScore(int pts);

    Vec3 getForward() const;
    Vec3 getRight() const;
};

} // namespace Sunshine
