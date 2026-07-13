#include "knowledge/KnowledgeLoop.hpp"
#include "knowledge/OntologyEngine.hpp"
#include "knowledge/EpistemologyEngine.hpp"

namespace RawrXD {
namespace Sovereign {
namespace Knowledge {

std::mutex KnowledgeLoop::s_mutex;
bool KnowledgeLoop::s_alive = false;
int KnowledgeLoop::s_tickCount = 0;

void KnowledgeLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    OntologyEngine::Init();
    EpistemologyEngine::Init();
    
    s_alive = true;
    s_tickCount = 0;
}

void KnowledgeLoop::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    OntologyEngine::OnTick();
    EpistemologyEngine::OnTick();
    
    s_tickCount++;
}

bool KnowledgeLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

nlohmann::json KnowledgeLoop::GetKnowledgeState() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json state;
    state["tickCount"] = s_tickCount;
    state["alive"] = s_alive;
    
    return state;
}

nlohmann::json KnowledgeLoop::GetKnowledgeMetrics() {
    nlohmann::json metrics;
    
    metrics["ontology"] = OntologyEngine::GetOntologyMetrics();
    metrics["epistemology"] = EpistemologyEngine::GetEpistemologyMetrics();
    
    return metrics;
}

} // namespace Knowledge
} // namespace Sovereign
} // namespace RawrXD
