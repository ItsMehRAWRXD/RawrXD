#include "social/SocialLoop.hpp"
#include "social/AgentCollaboration.hpp"
#include "social/KnowledgeSharing.hpp"
#include "social/ConsensusBuilding.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void SocialLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    AgentCollaboration::Init();
    KnowledgeSharing::Init();
    ConsensusBuilding::Init();
    s_initialized = true;
}

void SocialLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all social components
    AgentCollaboration::OnTick();
    KnowledgeSharing::OnTick();
    ConsensusBuilding::OnTick();
}

bool SocialLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
