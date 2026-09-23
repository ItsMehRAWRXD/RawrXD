#include "neonsiege_core.hpp"
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <string>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace NeonSiege {

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------
static const char* kLogFile = "neonsiege_events.txt";
static const char* kSummaryFile = "neonsiege_summary.txt";

void logEvent(const std::string& event) {
    FILE* f = nullptr;
    fopen_s(&f, kLogFile, "a");
    if (f) {
        fprintf(f, "[%f] %s\n", (double)GetTickCount64() / 1000.0, event.c_str());
        fflush(f);
        fclose(f);
    }
}

void logTelemetrySummary(const GameSession& game) {
    FILE* f = nullptr;
    fopen_s(&f, kSummaryFile, "w");
    if (!f) return;
    fprintf(f, "=== NEON SIEGE SUMMARY ===\n");
    fprintf(f, "WAVE=%d\n", game.wave);
    fprintf(f, "SCORE=%d\n", game.score);
    fprintf(f, "KILLS=%d\n", game.totalKills);
    fprintf(f, "LIVES=%d\n", game.player.lives);
    fprintf(f, "HEALTH=%d\n", game.player.health);
    fprintf(f, "STATE=%s\n",
        game.state == GameState::Victory ? "VICTORY" :
        game.state == GameState::GameOver ? "GAME_OVER" : "OTHER");
    fclose(f);
}

// ---------------------------------------------------------------------------
// Arena helpers
// ---------------------------------------------------------------------------
void buildArena(std::vector<AABB>& boxes) {
    boxes.clear();
    // Dark neon arena: large floor, walls, plus central pillars for cover
    // North
    { AABB b; b.min = Vec3(-30.0f, 0.0f, -30.0f); b.max = Vec3(30.0f, 2.5f, -28.0f); boxes.push_back(b); }
    // South
    { AABB b; b.min = Vec3(-30.0f, 0.0f,  28.0f); b.max = Vec3(30.0f, 2.5f,  30.0f); boxes.push_back(b); }
    // West
    { AABB b; b.min = Vec3(-30.0f, 0.0f, -30.0f); b.max = Vec3(-28.0f, 2.5f,  30.0f); boxes.push_back(b); }
    // East
    { AABB b; b.min = Vec3( 28.0f, 0.0f, -30.0f); b.max = Vec3( 30.0f, 2.5f,  30.0f); boxes.push_back(b); }
    // Center pillars
    { AABB b; b.min = Vec3(-5.0f, 0.0f, -5.0f); b.max = Vec3(-3.0f, 2.5f, -3.0f); boxes.push_back(b); }
    { AABB b; b.min = Vec3(3.0f, 0.0f, 3.0f); b.max = Vec3(5.0f, 2.5f, 5.0f); boxes.push_back(b); }
    { AABB b; b.min = Vec3(3.0f, 0.0f, -5.0f); b.max = Vec3(5.0f, 2.5f, -3.0f); boxes.push_back(b); }
    { AABB b; b.min = Vec3(-5.0f, 0.0f, 3.0f); b.max = Vec3(-3.0f, 2.5f, 5.0f); boxes.push_back(b); }
}

Vec3 getRandomSpawn(const std::vector<Vec3>& spawns) {
    if (spawns.empty()) return Vec3(0.0f, 0.0f, 0.0f);
    int idx = rand() % (int)spawns.size();
    return spawns[idx];
}

// ---------------------------------------------------------------------------
// Enemy
// ---------------------------------------------------------------------------
void Enemy::spawn(const Vec3& pos_, float startYaw, EnemyType t) {
    type = t;
    spawnPos = pos_;
    pos = pos_;
    yaw = startYaw;
    alive = true;
    respawnTimer = 0.0f;
    lastFireTime = -999.0f;

    switch (t) {
    case EnemyType::Grunt:
        maxHealth = 60;
        health = 60;
        moveSpeed = 5.0f;
        turnSpeed = 180.0f;
        fireRange = 15.0f;
        fireCooldown = 0.4f;
        damage = 10;
        color = 0xFF00FF00; // green
        break;
    case EnemyType::Gunner:
        maxHealth = 80;
        health = 80;
        moveSpeed = 3.0f;
        turnSpeed = 120.0f;
        fireRange = 35.0f;
        fireCooldown = 0.2f;
        damage = 15;
        color = 0xFF00FFFF; // cyan
        break;
    case EnemyType::Tank:
        maxHealth = 250;
        health = 250;
        moveSpeed = 1.5f;
        turnSpeed = 60.0f;
        fireRange = 20.0f;
        fireCooldown = 1.2f;
        damage = 25;
        color = 0xFFFF8800; // orange
        break;
    }
}

Vec3 Enemy::getForward() const {
    float rad = yaw * 3.14159265f / 180.0f;
    return Vec3(std::sin(rad), 0.0f, -std::cos(rad));
}

void Enemy::update(float dt, const Vec3& targetPos, const std::vector<AABB>& boxes, double now) {
    if (!alive) {
        respawnTimer -= dt;
        if (respawnTimer <= 0.0f) {
            spawn(spawnPos, yaw, type);
        }
        return;
    }

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

    // Movement
    if (dist > 2.5f) {
        Vec3 f = getForward();
        pos = pos + f * (moveSpeed * dt);
    }

    // Fire at player
    if (dist <= fireRange && canFire(now)) {
        lastFireTime = (float)now;
        // We deal damage in GameSession::update for consistency
    }
}

void Enemy::takeDamage(int dmg) {
    if (!alive) return;
    health -= dmg;
    if (health <= 0) {
        health = 0;
        alive = false;
        respawnTimer = 3.0f;
    }
}

// ---------------------------------------------------------------------------
// Player
// ---------------------------------------------------------------------------
void Player::spawn(const Vec3& pos, float startYaw) {
    spawnPos = pos;
    camera.setPosition(pos + Vec3(0.0f, 1.6f, 0.0f));
    camera.setLookAt(pos + Vec3(0.0f, 1.6f, -1.0f));
    camera.setUp(Vec3(0.0f, 1.0f, 0.0f));
    yaw = startYaw;
    pitch = 0.0f;
    health = maxHealth;
    alive = true;
    respawnTimer = 0.0f;
    fireCooldown = 0.15f;
    lastFireTime = -999.0f;
    weaponDamage = 100;
    moveSpeedMultiplier = 1.0f;
    overdriveTimer = 0.0f;
    damageFlashTimer = 0.0f;
    logEvent("PLAYER_RESPAWN");
}

void Player::takeDamage(int dmg) {
    if (!alive) return;
    health -= dmg;
    damageFlashTimer = 0.2f;
    logEvent("PLAYER_DAMAGE");
    if (health <= 0) {
        health = 0;
        alive = false;
        if (lives > 0) {
            lives--;
            respawnTimer = 2.0f;
        }
        logEvent("PLAYER_DEATH");
    }
}

void Player::update(float dt) {
    if (fireCooldown > 0.0f) fireCooldown -= dt;
    if (overdriveTimer > 0.0f) {
        overdriveTimer -= dt;
        if (overdriveTimer < 0.0f) {
            overdriveTimer = 0.0f;
            fireCooldown = 0.15f; // reset
        }
    }
    if (damageFlashTimer > 0.0f) damageFlashTimer -= dt;
    if (!alive) {
        respawnTimer -= dt;
        if (respawnTimer <= 0.0f && lives >= 0) {
            spawn(spawnPos, yaw);
        }
    }
}

void Player::addScore(int pts) {
    score += pts;
}

// ---------------------------------------------------------------------------
// GameSession
// ---------------------------------------------------------------------------
void GameSession::init(bool deterministic_) {
    deterministic = deterministic_;
    state = GameState::Menu;
    wave = 1;
    score = 0;
    totalKills = 0;
    enemiesAlive = 0;
    waveTimer = 0.0f;

    // Clear log
    FILE* f = nullptr;
    fopen_s(&f, kLogFile, "w");
    if (f) fclose(f);

    buildArena(arenaBoxes);

    // Spawn points scattered around arena
    spawnPoints.clear();
    spawnPoints.push_back(Vec3(0.0f, 0.0f, 0.0f));
    spawnPoints.push_back(Vec3(15.0f, 0.0f, 15.0f));
    spawnPoints.push_back(Vec3(-15.0f, 0.0f, 15.0f));
    spawnPoints.push_back(Vec3(15.0f, 0.0f, -15.0f));
    spawnPoints.push_back(Vec3(-15.0f, 0.0f, -15.0f));
    spawnPoints.push_back(Vec3(20.0f, 0.0f, 0.0f));
    spawnPoints.push_back(Vec3(-20.0f, 0.0f, 0.0f));
    spawnPoints.push_back(Vec3(0.0f, 0.0f, 20.0f));
    spawnPoints.push_back(Vec3(0.0f, 0.0f, -20.0f));

    enemies.clear();
    pickups.clear();
}

void GameSession::startGame() {
    player.lives = 3;
    player.score = 0;
    player.kills = 0;
    wave = 1;
    score = 0;
    totalKills = 0;
    state = GameState::Playing;
    logEvent("GAME_START");
    startWave();
}

void GameSession::startWave() {
    enemies.clear();
    pickups.clear();
    enemiesAlive = 0;
    waveTimer = 0.0f;

    int count = 0;
    int gruntCount = 0, gunnerCount = 0, tankCount = 0;

    if (wave == 1) {
        count = 5; gruntCount = 5;
    } else if (wave == 2) {
        count = 8; gruntCount = 5; gunnerCount = 3;
    } else if (wave == 3) {
        count = 12; gruntCount = 6; gunnerCount = 4; tankCount = 2;
    } else if (wave == 4) {
        // Boss wave
        state = GameState::BossFight;
        count = 4; gruntCount = 4;
        for (int i = 0; i < count; ++i) {
            spawnEnemy(EnemyType::Grunt, getRandomSpawn(spawnPoints));
        }
        // Spawn boss as an oversized Tank
        Enemy boss;
        boss.spawn(Vec3(0.0f, 0.0f, -10.0f), 0.0f, EnemyType::Tank);
        boss.maxHealth = 600;
        boss.health = 600;
        boss.moveSpeed = 1.2f;
        boss.fireRange = 30.0f;
        boss.fireCooldown = 0.8f;
        boss.damage = 30;
        boss.color = 0xFFFF00FF; // magenta boss
        enemies.push_back(boss);
        enemiesAlive = count + 1;
        logEvent("BOSS_SPAWN");
        logEvent("WAVE_START wave=" + std::to_string(wave));
        return;
    }

    // Spawn grunts
    for (int i = 0; i < gruntCount; ++i) {
        spawnEnemy(EnemyType::Grunt, getRandomSpawn(spawnPoints));
    }
    // Spawn gunners
    for (int i = 0; i < gunnerCount; ++i) {
        spawnEnemy(EnemyType::Gunner, getRandomSpawn(spawnPoints));
    }
    // Spawn tanks
    for (int i = 0; i < tankCount; ++i) {
        spawnEnemy(EnemyType::Tank, getRandomSpawn(spawnPoints));
    }

    enemiesAlive = count;
    logEvent("WAVE_START wave=" + std::to_string(wave));
}

void GameSession::spawnEnemy(EnemyType type, const Vec3& pos) {
    Enemy e;
    e.spawn(pos, 0.0f, type);
    enemies.push_back(e);
    std::string typeStr = (type == EnemyType::Grunt) ? "GRUNT" : ((type == EnemyType::Gunner) ? "GUNNER" : "TANK");
    logEvent("BOT_SPAWN type=" + typeStr);
}

void GameSession::dropPickup(const Vec3& pos) {
    int r = rand() % 100;
    Pickup p;
    p.pos = pos;
    p.active = true;
    p.bobTime = 0.0f;
    if (r < 25) {
        p.type = PickupType::Health;
        p.color = 0xFF00FF00; // green
    } else if (r < 45) {
        p.type = PickupType::FireRate;
        p.color = 0xFF00FFFF; // cyan
    } else if (r < 65) {
        p.type = PickupType::Damage;
        p.color = 0xFFFF0000; // red
    } else if (r < 85) {
        p.type = PickupType::Speed;
        p.color = 0xFFFFFF00; // yellow
    } else {
        p.type = PickupType::Overdrive;
        p.color = 0xFFFF00FF; // purple
    }
    pickups.push_back(p);
    logEvent("PICKUP_SPAWN");
}

void GameSession::collectPickups() {
    Vec3 pp = player.camera.getPosition();
    for (auto& p : pickups) {
        if (!p.active) continue;
        Vec3 d = p.pos - pp;
        float dist = std::sqrt(d.x * d.x + d.z * d.z);
        if (dist < 1.8f) {
            p.active = false;
            logEvent("PICKUP_COLLECT");
            switch (p.type) {
            case PickupType::Health:
                player.health = (player.health + 30 < player.maxHealth) ? (player.health + 30) : player.maxHealth;
                logEvent("PLAYER_HEAL");
                break;
            case PickupType::FireRate:
                player.fireCooldown = (player.fireCooldown * 0.8f > 0.04f) ? (player.fireCooldown * 0.8f) : 0.04f;
                break;
            case PickupType::Damage:
                player.weaponDamage += 25;
                break;
            case PickupType::Speed:
                player.moveSpeedMultiplier = (player.moveSpeedMultiplier + 0.25f < 2.0f) ? (player.moveSpeedMultiplier + 0.25f) : 2.0f;
                break;
            case PickupType::Overdrive:
                player.overdriveTimer = 5.0f;
                player.fireCooldown = 0.04f;
                break;
            }
        }
    }
}

void GameSession::playerFire(double now) {
    if (state != GameState::Playing && state != GameState::BossFight) return;
    if (!player.alive) return;
    if (!player.canFire(now)) return;

    logEvent("PLAYER_FIRE");
    player.lastFireTime = (float)now;

    Vec3 origin = player.camera.getPosition();
    Vec3 dir = player.camera.getForward();

    // Raycast against enemies
    float bestT = 1e9f;
    int hitIdx = -1;
    for (size_t i = 0; i < enemies.size(); ++i) {
        if (!enemies[i].alive) continue;
        Sphere s;
        s.center = enemies[i].pos + Vec3(0.0f, 1.2f, 0.0f);
        s.radius = 0.6f;
        float t = 0.0f;
        if (raySphereIntersect(origin, dir, s, &t)) {
            if (t < bestT) {
                bestT = t;
                hitIdx = (int)i;
            }
        }
    }

    if (hitIdx >= 0) {
        enemies[hitIdx].takeDamage(player.weaponDamage);
        logEvent("BOT_DAMAGE");
        if (!enemies[hitIdx].alive) {
            player.addScore(100);
            player.kills++;
            score += 100;
            totalKills++;
            enemiesAlive--;
            logEvent("BOT_DEATH");
            // Drop pickup sometimes
            if ((rand() % 100) < 30) {
                dropPickup(enemies[hitIdx].pos);
            }
        }
    }
}

void GameSession::update(float dt, double now) {
    if (state == GameState::Menu) return;
    if (state == GameState::Victory || state == GameState::GameOver) return;

    player.update(dt);
    if (!player.alive && player.lives < 0) {
        state = GameState::GameOver;
        logEvent("GAME_OVER");
        logTelemetrySummary(*this);
        return;
    }

    // Update enemies
    Vec3 targetPos = player.camera.getPosition();
    for (auto& e : enemies) {
        e.update(dt, targetPos, arenaBoxes, now);
        if (e.alive && e.canFire(now)) {
            // Simple fire check: distance + line of sight
            Vec3 toP = targetPos - e.pos;
            float dist = std::sqrt(toP.x * toP.x + toP.z * toP.z);
            if (dist <= e.fireRange) {
                // check line of sight
                bool blocked = false;
                for (const auto& box : arenaBoxes) {
                    float t = 0.0f;
                    if (rayAABBIntersect(e.pos + Vec3(0.0f, 1.6f, 0.0f), toP * (1.0f / dist), box, &t)) {
                        if (t < dist) { blocked = true; break; }
                    }
                }
                if (!blocked) {
                    player.takeDamage(e.damage);
                    e.lastFireTime = (float)now;
                }
            }
        }
    }

    collectPickups();

    // Wave progression
    if (enemiesAlive <= 0) {
        if (wave >= maxWaves) {
            state = GameState::Victory;
            logEvent("VICTORY");
            logTelemetrySummary(*this);
            return;
        }
        // Intermission before next wave
        state = GameState::WaveComplete;
        waveIntermission = 3.0f;
        logEvent("WAVE_COMPLETE");
        return;
    }

    // Intermission countdown
    if (state == GameState::WaveComplete) {
        waveIntermission -= dt;
        if (waveIntermission <= 0.0f) {
            ++wave;
            state = GameState::Playing;
            startWave();
        }
    }
}

void GameSession::restartGame() {
    logEvent("GAME_RESTART");
    init(deterministic);
    startGame();
}

bool GameSession::checkWinCondition() const {
    return state == GameState::Victory;
}

bool GameSession::checkLossCondition() const {
    return state == GameState::GameOver;
}

} // namespace NeonSiege
