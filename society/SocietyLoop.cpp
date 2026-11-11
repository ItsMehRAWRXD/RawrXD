#include "society/SocietyLoop.hpp"
#include "society/AgentGuild.hpp"
#include "society/SocialContract.hpp"
#include "society/AgentNegotiation.hpp"

namespace RawrXD {
namespace Sovereign {
namespace Society {

std::mutex SocietyLoop::s_mutex;
bool SocietyLoop::s_alive = false;
int SocietyLoop::s_tickCount = 0;

void SocietyLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    AgentGuild::Init();
    SocialContract::Init();
    AgentNegotiation::Init();
    
    s_alive = true;
    s_tickCount = 0;
}

void SocietyLoop::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    AgentGuild::OnTick();
    SocialContract::OnTick();
    AgentNegotiation::OnTick();
    
    s_tickCount++;
}

bool SocietyLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

nlohmann::json SocietyLoop::GetSocietyState() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json state;
    state["tickCount"] = s_tickCount;
    state["alive"] = s_alive;
    
    return state;
}

nlohmann::json SocietyLoop::GetSocietyMetrics() {
    nlohmann::json metrics;
    
    metrics["guilds"] = AgentGuild::GetSocietyMetrics();
    metrics["contracts"] = SocialContract::GetContractMetrics();
    metrics["negotiations"] = AgentNegotiation::GetNegotiationMetrics();
    
    return metrics;
}

} // namespace Society
} // namespace Sovereign
} // namespace RawrXD
