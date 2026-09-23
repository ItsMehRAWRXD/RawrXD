#include "Game.hpp"
#include <cstdio>
#include <cmath>
#include <windows.h>

namespace Sunshine {

static void logEvent(const char* event) {
    FILE* f = nullptr;
    fopen_s(&f, "instagib_events.txt", "a");
    if (f) { fprintf(f, "[%f] %s\n", (double)GetTickCount64() / 1000.0, event); fflush(f); fclose(f); }
}

void GameRules::init() {
    // Clear event log for fresh telemetry
    FILE* f = nullptr; fopen_s(&f, "instagib_events.txt", "w");
    if (f) fclose(f);

    mode = GameMode::Deathmatch;
    scoreLimit = 2;
    timeLimit = 10.0f;
    matchTime = 0.0f;
    matchOver = false;

    // Build a simple arena: four walls and some obstacles
    arena.addBox(Vec3(-20.0f, 0.0f, -20.0f), Vec3(20.0f, 2.0f, -18.0f)); // north wall
    arena.addBox(Vec3(-20.0f, 0.0f,  18.0f), Vec3(20.0f, 2.0f,  20.0f)); // south wall
    arena.addBox(Vec3(-20.0f, 0.0f, -20.0f), Vec3(-18.0f, 2.0f, 20.0f)); // west wall
    arena.addBox(Vec3( 18.0f, 0.0f, -20.0f), Vec3( 20.0f, 2.0f, 20.0f)); // east wall
    // center block removed for open combat test

    // Player facing -Z; bot placed directly in front at -Z for instant LOS
    arena.addSpawn(Vec3(0.0f, 0.0f, 5.0f), 0.0f);   // player
    arena.addSpawn(Vec3(0.0f, 0.0f, -5.0f), 180.0f); // bot directly ahead
    arena.addSpawn(Vec3(5.0f, 0.0f, 0.0f), 270.0f);
    arena.addSpawn(Vec3(-5.0f, 0.0f, 0.0f), 90.0f);

    // Spawn player
    Vec3 pPos; float pYaw;
    if (arena.findSpawn(0, &pPos, &pYaw)) {
        player.spawn(pPos, pYaw);
    }

    // Spawn bots close for rapid combat
    Bot b;
    if (arena.findSpawn(1, &pPos, &pYaw)) { b.spawn(pPos, pYaw); bots.push_back(b); }
    if (arena.findSpawn(2, &pPos, &pYaw)) { b.spawn(pPos, pYaw); bots.push_back(b); }
}

void GameRules::update(float dt, double now) {
    if (matchOver) return;

    matchTime += dt;
    player.update(dt);

    std::vector<Sphere> botSpheres;
    for (auto& bot : bots) {
        if (bot.alive) {
            bot.update(dt, player.camera.getPosition(), arena, now, &weapon, &player);
            Sphere s;
            s.center = bot.pos + Vec3(0.0f, 1.6f, 0.0f);
            s.radius = 0.5f;
            botSpheres.push_back(s);
        } else {
            bot.update(dt, player.camera.getPosition(), arena, now, nullptr, &player);
        }
    }

    // Check win conditions
    if (!matchOver && (player.score >= scoreLimit || matchTime >= timeLimit)) {
        matchOver = true;
        logEvent(player.score >= scoreLimit ? "MATCH_WIN" : "MATCH_END_TIME");
    }
}

void GameRules::playerFire(double now) {
    if (matchOver || !player.alive) return;
    if (!weapon.canFire(now)) return;

    logEvent("PLAYER_FIRE");
    Vec3 origin = player.camera.getPosition();
    Vec3 dir = player.camera.getForward();
    Vec3 hitPos;
    int hitId = -1;

    std::vector<Sphere> botSpheres;
    for (auto& bot : bots) {
        Sphere s;
        s.center = bot.pos + Vec3(0.0f, 1.6f, 0.0f);
        s.radius = 0.5f;
        botSpheres.push_back(s);
    }

    bool hit = weapon.raycast(origin, dir,
                              arena.boxes.data(), (int)arena.boxes.size(),
                              botSpheres.data(), (int)botSpheres.size(),
                              &hitPos, &hitId);
    if (hit) {
        int boxCount = (int)arena.boxes.size();
        if (hitId >= boxCount && hitId < boxCount + (int)bots.size()) {
            int botIdx = hitId - boxCount;
            bots[botIdx].takeDamage(weapon.damage);
            logEvent("BOT_HIT");
            if (!bots[botIdx].alive) {
                player.addScore(1);
                logEvent("BOT_KILL");
            }
        }
    }
    weapon.fire(now);
}

void GameRules::resetMatch() {
    matchTime = 0.0f;
    matchOver = false;
    player.score = 0;
    Vec3 pPos; float pYaw;
    if (arena.findSpawn(0, &pPos, &pYaw)) player.spawn(pPos, pYaw);
    for (size_t i = 0; i < bots.size(); ++i) {
        if (arena.findSpawn((int)(i + 1), &pPos, &pYaw)) {
            bots[i].spawn(pPos, pYaw);
        }
    }
}

int GameRules::getWinnerScore() const {
    return player.score;
}

} // namespace Sunshine
