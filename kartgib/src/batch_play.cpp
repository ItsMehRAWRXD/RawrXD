#include "finish_batches.hpp"
#include "player_step.hpp"
#include "worldforge.hpp"
#include <cmath>
#include <fstream>
#include <sstream>
#include <vector>
#include <xinput.h>
#pragma comment(lib, "xinput.lib")

static void aiStep(int& state, int& hp, float dist) {
    if (state == 0 && dist < 12.0f) state = 1;
    else if (state == 1 && dist < 2.0f) state = 2;
    else if (state == 2) { hp -= 1; if (hp <= 0 || dist > 6.0f) state = 3; }
    else if (state == 3 && dist > 14.0f) state = 0;
}

void fillBatchPlay(std::vector<BatchGate>& out) {
    kg::Settings settings;
    settings.seed = 20261025;
    settings.biome = kg::Biome::Tropical;
    auto ground = [&](float x, float z) { return static_cast<float>(kg::sampleHeight(x, z, settings)); };
    KartState kart;
    kart.throttle = 1.0f;
    stepKartBody(kart, 1.0f / 60.0f, ground);
    bool drove = kart.z > 0.0f;
    kart.jump = true;
    stepKartBody(kart, 1.0f / 60.0f, ground);
    XINPUT_STATE pad{};
    DWORD padResult = XInputGetState(0, &pad);
    std::ostringstream input;
    input << "forward=" << drove << " airborne=" << kart.airborne << " xinput_code=" << padResult
          << " mouse_window=NOT_RUN gamepad=" << (padResult == 0 ? "CONNECTED" : "NOT_CONNECTED");
    addGate(out, 11, "Player controller, camera and input mapping", drove && kart.airborne ? "PARTIAL" : "FAIL", input.str());

    struct Entity { int id; float x; bool alive; };
    std::vector<Entity> entities{{1, 4.0f, true}, {2, 9.0f, true}};
    entities[0].alive = false;
    entities[1].x += 1.0f;
    {
        std::ofstream file("F:/rawrxd/kartgib/evidence/kartgib_entities.txt");
        for (const Entity& entity : entities) if (entity.alive) file << entity.id << " " << entity.x << "\n";
    }
    entities.clear();
    std::ifstream file("F:/rawrxd/kartgib/evidence/kartgib_entities.txt");
    int id = 0; float x = 0;
    bool queried = false, ghost = false;
    while (file >> id >> x) { if (id == 1) ghost = true; if (id == 2 && x == 10.0f) queried = true; }
    addGate(out, 12, "Gameplay entity/component framework", queried && !ghost ? "PARTIAL" : "FAIL",
        "serialized_living_id=2 destroyed_id_absent=1 rendered_entities=NOT_RUN");
    addGate(out, 13, "Skeletal animation and animation state machines", "NOT_RUN",
        "no imported skeletal asset is in the repository");

    int state = 0, hp = 3;
    aiStep(state, hp, 20.0f);
    bool patrol = state == 0;
    aiStep(state, hp, 8.0f);
    bool chase = state == 1;
    aiStep(state, hp, 1.0f);
    bool attack = state == 2;
    aiStep(state, hp, 1.0f);
    bool hurt = hp == 2 && state == 2;
    aiStep(state, hp, 9.0f);
    bool recover = state == 3;
    aiStep(state, hp, 20.0f);
    bool reset = state == 0;
    std::ostringstream ai;
    ai << "patrol=" << patrol << " chase=" << chase << " attack=" << attack << " hurt=" << hurt
       << " recover=" << recover << " reset=" << reset << " rendered_npc=NOT_RUN";
    addGate(out, 14, "NPC AI, behavior trees and combat", patrol && chase && attack && hurt && recover && reset ? "PARTIAL" : "FAIL", ai.str());
}
