#include "Player.hpp"
#include <cstdio>
#include <windows.h>

namespace Sunshine {

static void logEvent(const char* event) {
    FILE* f = nullptr;
    fopen_s(&f, "instagib_events.txt", "a");
    if (f) { fprintf(f, "[%f] %s\n", (double)GetTickCount64() / 1000.0, event); fflush(f); fclose(f); }
}

void Player::spawn(const Vec3& pos, float startYaw) {
    spawnPos = pos;
    camera.setPosition(pos + Vec3(0.0f, 1.6f, 0.0f));
    camera.setLookAt(pos + Vec3(0.0f, 1.6f, -1.0f));
    camera.setUp(Vec3(0.0f, 1.0f, 0.0f));
    yaw = startYaw;
    pitch = 0.0f;
    health = 100;
    alive = true;
    respawnTimer = 0.0f;
    fireCooldown = 0.0f;
    logEvent("PLAYER_RESPAWN");
}

void Player::takeDamage(int dmg) {
    if (!alive) return;
    health -= dmg;
    logEvent("PLAYER_DAMAGE");
    if (health <= 0) {
        health = 0;
        alive = false;
        respawnTimer = 3.0f;
        logEvent("PLAYER_DEATH");
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
