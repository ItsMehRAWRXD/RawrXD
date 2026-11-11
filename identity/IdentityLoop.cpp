#include "identity/IdentityLoop.hpp"
#include "identity/IdentityModel.hpp"
#include "identity/ContinuityManager.hpp"
#include "identity/GoalPersistence.hpp"
#include "identity/MemoryAlignment.hpp"
#include "stability/MetaStabilityLoop.hpp"
#include "consciousness/SelfModel.hpp"

void IdentityLoop::Init() {
    IdentityModel::Init();
    ContinuityManager::Init();
    GoalPersistence::Init();
    MemoryAlignment::Init();
}

void IdentityLoop::Tick() {
    // Ensure identity is stable
    if (!IsIdentityIntact()) {
        // Trigger restoration from last checkpoint
        auto last = ContinuityManager::GetLastCheckpoint();
        if (!last.is_null() && last.contains("hash")) {
            ContinuityManager::Restore(last["hash"]);
        }
    }
    
    // Align memories with identity
    MemoryAlignment::AlignMemory();
    
    // Align goals with identity
    GoalPersistence::AlignGoalsWithIdentity();
    
    // Create checkpoint if stable
    if (MetaStabilityLoop::IsStable() && MemoryAlignment::IsAligned()) {
        ContinuityManager::Checkpoint();
    }
    
    // Update self-model with identity status
    SelfModel::Update({
        {"identity_hash", IdentityModel::GetIdentityHash()},
        {"continuity_status", ContinuityManager::GetContinuityStatus()},
        {"memory_aligned", MemoryAlignment::IsAligned()},
        {"persistent_goals", GoalPersistence::GetPersistentGoals().size()}
    });
}

void IdentityLoop::Shutdown() {
    // Final checkpoint before shutdown
    ContinuityManager::Checkpoint();
}

bool IdentityLoop::IsIdentityIntact() {
    auto identity = IdentityModel::GetCoreIdentity();
    return IdentityModel::ValidateIdentity(identity) &&
           MemoryAlignment::IsAligned() &&
           ContinuityManager::GetContinuityStatus() != "drifted";
}
