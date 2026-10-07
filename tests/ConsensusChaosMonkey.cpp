#include "tests/ConsensusChaosMonkey.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include "sovereign/SovereignConsensus.hpp"
#include <random>

static std::mt19937 rng;
static bool chaosRunning = false;

void ConsensusChaosMonkey::Init() {
    rng.seed(static_cast<unsigned>(Beaconism::GetTimestamp()));
}

void ConsensusChaosMonkey::InjectLatencySpike(uint64_t delayMs) {
    Fabric::BroadcastJSON({
        {"type", "chaos_latency"},
        {"delay_ms", delayMs},
        {"timestamp", Beaconism::GetTimestamp()}
    });
    
    Beaconism::Emit(Beaconism::BEACON_ChaosInjected, {
        {"type", "latency_spike"},
        {"delay_ms", delayMs}
    });
}

void ConsensusChaosMonkey::DropRandomVote() {
    Fabric::BroadcastJSON({
        {"type", "chaos_drop_vote"},
        {"timestamp", Beaconism::GetTimestamp()}
    });
    
    Beaconism::Emit(Beaconism::BEACON_ChaosInjected, {
        {"type", "dropped_vote"}
    });
}

void ConsensusChaosMonkey::DuplicateRandomVote() {
    Fabric::BroadcastJSON({
        {"type", "chaos_duplicate_vote"},
        {"timestamp", Beaconism::GetTimestamp()}
    });
    
    Beaconism::Emit(Beaconism::BEACON_ChaosInjected, {
        {"type", "duplicate_vote"}
    });
}

void ConsensusChaosMonkey::CorruptRandomMessage() {
    Fabric::BroadcastJSON({
        {"type", "chaos_corrupt"},
        {"corrupted", true},
        {"timestamp", Beaconism::GetTimestamp()}
    });
    
    Beaconism::Emit(Beaconism::BEACON_ChaosInjected, {
        {"type", "corrupted_message"}
    });
}

void ConsensusChaosMonkey::StartRandomChaos(int intervalMs) {
    chaosRunning = true;
    
    Fabric::BroadcastJSON({
        {"type", "chaos_start"},
        {"interval_ms", intervalMs},
        {"timestamp", Beaconism::GetTimestamp()}
    });
}

void ConsensusChaosMonkey::StopChaos() {
    chaosRunning = false;
    
    Fabric::BroadcastJSON({
        {"type", "chaos_stop"},
        {"timestamp", Beaconism::GetTimestamp()}
    });
}
