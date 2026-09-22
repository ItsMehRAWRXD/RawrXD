#include "Bot.hpp"
#include "Arena.hpp"
#include "Weapon.hpp"
#include <cmath>

namespace Sunshine {

void Bot::spawn(const Vec3& spawnPosition, float startYaw) {
    spawnPos = spawnPosition;
    pos = spawnPosition;
    yaw = startYaw;
    health = 100;
    alive = true;
    respawnTimer = 0.0f;
    fireCooldown = 0.0f;
    thinkTimer = 0.0f;
}

Vec3 Bot::getForward() const {
    float rad = yaw * 3.14159265f / 180.0f;
    return Vec3(std::sin(rad), 0.0f, -std::cos(rad));
}

Vec3 Bot::getRight() const {
    float rad = yaw * 3.14159265f / 180.0f;
    return Vec3(std::cos(rad), 0.0f, std::sin(rad));
}

void Bot::update(float dt, const Vec3& targetPos, const Arena& arena, double now, Weapon* weapon) {
    if (!alive) {
        respawnTimer -= dt;
        if (respawnTimer <= 0.0f) {
            spawn(spawnPos, yaw);
        }
        return;
    }

    // Simple AI: turn toward target, move if far, fire if in range and facing
    Vec3 toTarget = targetPos - pos;
    float dist = std::sqrt(toTarget.x * toTarget.x + toTarget.z * toTarget.z);
    Vec3 flatTo = Vec3(toTarget.x, 0.0f, toTarget.z);
    if (dist > 0.01f) {
        float desiredYaw = std::atan2(flatTo.x, -flatTo.z) * 180.0f / 3.14159265f;
        float delta = desiredYaw - yaw;
        while (delta > 180.0f) delta -= 360.0f;
        while (delta < -180.0f) delta += 360.0f;
        float maxTurn = turnSpeed * dt;
        if (delta > maxTurn) delta = maxTurn;
        if (delta < -maxTurn) delta = -maxTurn;
        yaw += delta;
    }

    if (dist > 3.0f) {
        Vec3 f = getForward();
        pos = pos + f * (moveSpeed * dt);
    }

    if (dist <= fireRange && weapon && weapon->canFire(now)) {
        // Check line of sight using a ray from bot to target
        Ray ray;
        ray.origin = pos + Vec3(0.0f, 1.6f, 0.0f);
        ray.dir = toTarget * (1.0f / dist);
        bool blocked = false;
        for (size_t i = 0; i < arena.boxes.size(); ++i) {
            float t = 0.0f;
            if (ray.intersectsAABB(arena.boxes[i], &t)) {
                if (t < dist) { blocked = true; break; }
            }
        }
        if (!blocked) {
            weapon->fire(now);
        }
    }
}

void Bot::takeDamage(int dmg) {
    if (!alive) return;
    health -= dmg;
    if (health <= 0) {
        health = 0;
        alive = false;
        respawnTimer = 3.0f;
    }
}

void Bot::addScore(int pts) {
    // bots don't track score in this slice
    (void)pts;
}

} // namespace Sunshine
