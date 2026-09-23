#pragma once

#include "sunshine/core/math.hpp"
#include "sunshine/core/Camera.hpp"
#include "sunshine/core/Primitives.hpp"
#include <vector>
#include <string>

namespace NeonSiege {

using namespace Sunshine;

enum class GameState {
    Menu,
    Playing,
    WaveComplete,
    BossFight,
    GameOver,
    Victory
};

enum class EnemyType {
    Grunt,
    Gunner,
    Tank
};

enum class PickupType {
    Health,
    FireRate,
    Damage,
    Speed,
    Overdrive
};

// Simple enemy using one struct with parameter sets
struct Enemy {
    Vec3 pos;
    Vec3 spawnPos;
    float yaw = 0.0f;
    int maxHealth = 100;
    int health = 100;
    bool alive = true;
    float respawnTimer = 0.0f;
    float lastFireTime = -999.0f;
    float moveSpeed = 2.0f;
    float turnSpeed = 90.0f;
    float fireRange = 40.0f;
    float fireCooldown = 0.15f;
    int damage = 20;
    EnemyType type = EnemyType::Grunt;
    uint32_t color = 0xFFFF0000; // default red

    void spawn(const Vec3& pos_, float startYaw, EnemyType t);
    void update(float dt, const Vec3& targetPos, const std::vector<AABB>& boxes, double now);
    void takeDamage(int dmg);
    Vec3 getForward() const;
    bool canFire(double now) const { return (float)(now - lastFireTime) >= fireCooldown; }
};

struct Pickup {
    Vec3 pos;
    PickupType type;
    bool active = true;
    float bobTime = 0.0f;
    uint32_t color = 0xFF00FF00;
};

struct Player {
    Camera camera;
    Vec3 spawnPos;
    float yaw = 0.0f;
    float pitch = 0.0f;
    int maxHealth = 100;
    int health = 100;
    int lives = 3;
    int score = 0;
    int kills = 0;
    bool alive = true;
    float respawnTimer = 0.0f;
    float fireCooldown = 0.15f;
    float lastFireTime = -999.0f;
    int weaponDamage = 100;
    float moveSpeedMultiplier = 1.0f;
    float overdriveTimer = 0.0f;
    float damageFlashTimer = 0.0f;

    void spawn(const Vec3& pos, float startYaw);
    void takeDamage(int dmg);
    void update(float dt);
    void addScore(int pts);
    bool canFire(double now) const { return (float)(now - lastFireTime) >= fireCooldown; }
};

struct GameSession {
    GameState state = GameState::Menu;
    int wave = 1;
    int maxWaves = 4;
    int score = 0;
    int totalKills = 0;
    int enemiesAlive = 0;
    float waveTimer = 0.0f;
    float waveIntermission = 3.0f;
    bool deterministic = false;

    Player player;
    std::vector<Enemy> enemies;
    std::vector<Pickup> pickups;
    std::vector<AABB> arenaBoxes;
    std::vector<Vec3> spawnPoints;

    void init(bool deterministic_);
    void startGame();
    void startWave();
    void update(float dt, double now);
    void playerFire(double now);
    void restartGame();
    void spawnEnemy(EnemyType type, const Vec3& pos);
    void dropPickup(const Vec3& pos);
    void collectPickups();
    bool checkWinCondition() const;
    bool checkLossCondition() const;
};

// Arena helpers
void buildArena(std::vector<AABB>& boxes);
Vec3 getRandomSpawn(const std::vector<Vec3>& spawns);

// Telemetry
void logEvent(const std::string& event);
void logTelemetrySummary(const GameSession& game);

// Intersection helpers
inline bool raySphereIntersect(const Vec3& origin, const Vec3& dir, const Sphere& s, float* outT) {
    Vec3 oc = origin - s.center;
    float b = oc.dot(dir);
    float c = oc.dot(oc) - s.radius * s.radius;
    float disc = b * b - c;
    if (disc < 0.0f) return false;
    float sqrtDisc = std::sqrt(disc);
    float t1 = -b - sqrtDisc;
    float t2 = -b + sqrtDisc;
    if (t1 > 0.0f) { *outT = t1; return true; }
    if (t2 > 0.0f) { *outT = t2; return true; }
    return false;
}

inline bool rayAABBIntersect(const Vec3& origin, const Vec3& dir, const AABB& box, float* outT) {
    float tMin = 0.0f, tMax = 1e9f;
    for (int i = 0; i < 3; ++i) {
        float o = (i == 0) ? origin.x : (i == 1) ? origin.y : origin.z;
        float d = (i == 0) ? dir.x   : (i == 1) ? dir.y   : dir.z;
        float bmin = (i == 0) ? box.min.x : (i == 1) ? box.min.y : box.min.z;
        float bmax = (i == 0) ? box.max.x : (i == 1) ? box.max.y : box.max.z;
        if (std::fabs(d) < 1e-6f) {
            if (o < bmin || o > bmax) return false;
        } else {
            float inv = 1.0f / d;
            float t1 = (bmin - o) * inv;
            float t2 = (bmax - o) * inv;
            if (t1 > t2) std::swap(t1, t2);
            if (t1 > tMin) tMin = t1;
            if (t2 < tMax) tMax = t2;
            if (tMin > tMax) return false;
        }
    }
    *outT = tMin;
    return true;
}

} // namespace NeonSiege
