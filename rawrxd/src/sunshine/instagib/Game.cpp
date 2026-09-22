#include "Game.hpp"
#include <cstdio>
#include <cmath>

namespace Sunshine {

void GameRules::init() {
    mode = GameMode::Deathmatch;
    scoreLimit = 20;
    timeLimit = 300.0f;
    matchTime = 0.0f;
    matchOver = false;

    // Build a simple arena: four walls and some obstacles
    arena.addBox(Vec3(-20.0f, 0.0f, -20.0f), Vec3(20.0f, 2.0f, -18.0f)); // north wall
    arena.addBox(Vec3(-20.0f, 0.0f,  18.0f), Vec3(20.0f, 2.0f,  20.0f)); // south wall
    arena.addBox(Vec3(-20.0f, 0.0f, -20.0f), Vec3(-18.0f, 2.0f, 20.0f)); // west wall
    arena.addBox(Vec3( 18.0f, 0.0f, -20.0f), Vec3( 20.0f, 2.0f, 20.0f)); // east wall
    arena.addBox(Vec3(-5.0f, 0.0f, -5.0f), Vec3(5.0f, 2.0f, 5.0f));      // center block

    arena.addSpawn(Vec3(-10.0f, 0.0f, -10.0f), 45.0f);
    arena.addSpawn(Vec3( 10.0f, 0.0f,  10.0f), 225.0f);
    arena.addSpawn(Vec3(-10.0f, 0.0f,  10.0f), 315.0f);
    arena.addSpawn(Vec3( 10.0f, 0.0f, -10.0f), 135.0f);

    // Spawn player
    Vec3 pPos; float pYaw;
    if (arena.findSpawn(0, &pPos, &pYaw)) {
        player.spawn(pPos, pYaw);
    }

    // Spawn bots
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
            bot.update(dt, player.camera.getPosition(), arena, now, &weapon);
            Sphere s;
            s.center = bot.pos + Vec3(0.0f, 1.6f, 0.0f);
            s.radius = 0.5f;
            botSpheres.push_back(s);
        } else {
            bot.update(dt, player.camera.getPosition(), arena, now, nullptr);
        }
    }

    // Check win conditions
    if (player.score >= scoreLimit || matchTime >= timeLimit) {
        matchOver = true;
    }
}

void GameRules::playerFire(double now) {
    if (matchOver || !player.alive) return;
    if (!weapon.canFire(now)) return;

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
            if (!bots[botIdx].alive) {
                player.addScore(1);
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
