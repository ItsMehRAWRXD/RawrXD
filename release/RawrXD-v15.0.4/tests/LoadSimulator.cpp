#include "tests/LoadSimulator.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include <math.h>

static bool running = false;
static float targetLoad = 0.5f;
static float currentLoad = 0.0f;

void LoadSimulator::Init() {}

void LoadSimulator::StartSimulation(float load) {
    running = true;
    targetLoad = load;
    
    Fabric::BroadcastJSON({
        {"type", "load_sim_start"},
        {"target_load", load},
        {"timestamp", Beaconism::GetTimestamp()}
    });
}

void LoadSimulator::StopSimulation() {
    running = false;
    currentLoad = 0.0f;
    
    Fabric::BroadcastJSON({
        {"type", "load_sim_stop"},
        {"timestamp", Beaconism::GetTimestamp()}
    });
}

bool LoadSimulator::IsRunning() {
    return running;
}

float LoadSimulator::GetCurrentLoad() {
    // Simulate load oscillation around target
    if (running) {
        currentLoad = targetLoad + (sinf(Beaconism::GetTimestamp() / 1000.0f) * 0.1f);
        if (currentLoad < 0) currentLoad = 0;
        if (currentLoad > 1) currentLoad = 1;
    }
    return currentLoad;
}
