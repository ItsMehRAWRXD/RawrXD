#include "sovereign/CrashRecovery.hpp"
#include "sovereign/Beaconism.hpp"
#include "sovereign/KVCache.hpp"
#include "sovereign/ExpertCache.hpp"
#include "sovereign/Replay.hpp"
#include <iostream>
#include <filesystem>

namespace Sovereign {
namespace CrashRecovery {

static constexpr const char* KV_STATE_FILE = "kv_state.bin";
static constexpr const char* EXPERT_STATE_FILE = "expert_state.bin";
static constexpr const char* REPLAY_STATE_FILE = "replay_state.bin";

void SaveState() {
    BeaconismEmitter::Instance().Emit(BeaconID::CrashSaveStart, 0);
    
    std::cout << "Saving runtime state...\n";
    
    KVCache::Save(KV_STATE_FILE);
    ExpertCache::Save(EXPERT_STATE_FILE);
    Replay::Save(REPLAY_STATE_FILE);
    
    std::cout << "State saved\n";
    BeaconismEmitter::Instance().Emit(BeaconID::CrashSaveDone, 0);
}

void LoadState() {
    BeaconismEmitter::Instance().Emit(BeaconID::CrashLoadStart, 0);
    
    std::cout << "Loading runtime state...\n";
    
    if (std::filesystem::exists(KV_STATE_FILE)) {
        KVCache::Load(KV_STATE_FILE);
    }
    
    if (std::filesystem::exists(EXPERT_STATE_FILE)) {
        ExpertCache::Load(EXPERT_STATE_FILE);
    }
    
    if (std::filesystem::exists(REPLAY_STATE_FILE)) {
        Replay::Load(REPLAY_STATE_FILE);
    }
    
    std::cout << "State loaded\n";
    BeaconismEmitter::Instance().Emit(BeaconID::CrashLoadDone, 0);
}

bool HasSavedState() {
    return std::filesystem::exists(KV_STATE_FILE) ||
           std::filesystem::exists(EXPERT_STATE_FILE) ||
           std::filesystem::exists(REPLAY_STATE_FILE);
}

void ClearState() {
    std::filesystem::remove(KV_STATE_FILE);
    std::filesystem::remove(EXPERT_STATE_FILE);
    std::filesystem::remove(REPLAY_STATE_FILE);
    std::cout << "Saved state cleared\n";
}

} // namespace CrashRecovery
} // namespace Sovereign
