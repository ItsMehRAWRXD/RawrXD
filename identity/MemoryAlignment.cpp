#include "identity/MemoryAlignment.hpp"
#include "cognition/LongTermMemory.hpp"
#include "cognition/EpisodicMemory.hpp"
#include "cognition/SemanticMemory.hpp"
#include "identity/IdentityModel.hpp"

void MemoryAlignment::Init() {}

void MemoryAlignment::AlignMemory() {
    // Ensure memories are consistent with identity
    auto identity = IdentityModel::GetCoreIdentity();
    
    // Align long-term memory with identity values
    auto ltm = LongTermMemory::Retrieve("identity_values");
    if (ltm.is_null()) {
        LongTermMemory::Store("identity_values", identity["values"]);
    }
}

float MemoryAlignment::ComputeAlignmentScore() {
    float score = 1.0f;
    
    // Check if episodic memories align with identity
    auto episodes = EpisodicMemory::GetAll();
    if (!episodes.empty()) {
        // stub: compute alignment between episodes and identity
        score *= 0.95f;
    }
    
    // Check if semantic relations align with identity
    auto identity = IdentityModel::GetCoreIdentity();
    if (identity.contains("purpose")) {
        auto relations = SemanticMemory::Query(identity["purpose"]);
        if (relations.empty()) {
            score *= 0.9f;
        }
    }
    
    return score;
}

bool MemoryAlignment::IsAligned() {
    return ComputeAlignmentScore() > 0.8f;
}

nlohmann::json MemoryAlignment::GetAlignmentReport() {
    return {
        {"score", ComputeAlignmentScore()},
        {"aligned", IsAligned()},
        {"episodes", EpisodicMemory::GetAll().size()},
        {"long_term_entries", 1} // stub
    };
}
