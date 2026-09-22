#include "Player.hpp"

namespace Sunshine {

void Player::spawn(const Vec3& pos, float startYaw) {
    spawnPos = pos;
    camera.setPosition(pos);
    camera.setLookAt(pos + Vec3(0.0f, 0.0f, -1.0f));
    camera.setUp(Vec3(0.0f, 1.0f, 0.0f));
    yaw = startYaw;
    pitch = 0.0f;
    health = 100;
    alive = true;
    respawnTimer = 0.0f;
    fireCooldown = 0.0f;
}

void Player::takeDamage(int dmg) {
    if (!alive) return;
    health -= dmg;
    if (health <= 0) {
        health = 0;
        alive = false;
        respawnTimer = 3.0f;
    }
}

void Player::update(float dt) {
    if (fireCooldown > 0.0f) {
        fireCooldown -= dt;
        if (fireCooldown < 0.0f) fireCooldown = 0.0f;
    }
    if (!alive) {
        respawnTimer -= dt;
        if (respawnTimer <= 0.0f) {
            spawn(spawnPos, yaw);
        }
    }
}

void Player::addScore(int pts) {
    score += pts;
}

} // namespace Sunshine
