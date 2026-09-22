#pragma once

#include "Player.hpp"
#include "Bot.hpp"
#include "Arena.hpp"
#include "Weapon.hpp"

namespace Sunshine {

enum class GameMode { Deathmatch };

struct GameRules {
    GameMode mode = GameMode::Deathmatch;
    int scoreLimit = 20;
    float timeLimit = 300.0f; // seconds
    float matchTime = 0.0f;
    bool matchOver = false;

    Player player;
    std::vector<Bot> bots;
    Arena arena;
    Weapon weapon;

    void init();
    void update(float dt, double now);
    void playerFire(double now);
    void resetMatch();
    int getWinnerScore() const;
};

} // namespace Sunshine
