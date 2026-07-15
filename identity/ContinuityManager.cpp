#include "identity/ContinuityManager.hpp"
#include "identity/IdentityModel.hpp"
#include "consciousness/SelfModel.hpp"
#include <deque>

static std::deque<nlohmann::json> checkpoints;
static const size_t MAX_CHECKPOINTS = 100;
static nlohmann::json lastCheckpoint;

void ContinuityManager::Init() {
    checkpoints.clear();
    lastCheckpoint = nlohmann::json::object();
}

void ContinuityManager::Checkpoint() {
    nlohmann::json cp = {
        {"timestamp", std::chrono::system_clock::now().time_since_epoch().count()},
        {"identity", IdentityModel::GetCoreIdentity()},
        {"self", SelfModel::Get()},
        {"hash", IdentityModel::GetIdentityHash()}
    };
    
    checkpoints.push_back(cp);
    if (checkpoints.size() > MAX_CHECKPOINTS) {
        checkpoints.pop_front();
    }
    
    lastCheckpoint = cp;
}

void ContinuityManager::Restore(const std::string& checkpointId) {
    for (auto& cp : checkpoints) {
        if (cp["hash"] == checkpointId) {
            IdentityModel::SetCoreIdentity(cp["identity"]);
            SelfModel::Update(cp["self"]);
            break;
        }
    }
}

nlohmann::json ContinuityManager::GetLastCheckpoint() {
    return lastCheckpoint;
}

bool ContinuityManager::HasContinuity() {
    return !checkpoints.empty();
}

std::string ContinuityManager::GetContinuityStatus() {
    if (!HasContinuity()) return "discontinuous";
    
    auto last = GetLastCheckpoint();
    if (last.contains("hash")) {
        std::string currentHash = IdentityModel::GetIdentityHash();
        if (last["hash"] == currentHash) {
            return "continuous";
        }
        return "drifted";
    }
    
    return "unknown";
}
