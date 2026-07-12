#include "society/AgentGuild.hpp"
#include <chrono>
#include <algorithm>

namespace RawrXD {
namespace Sovereign {
namespace Society {

std::vector<Guild> AgentGuild::s_guilds;
std::mutex AgentGuild::s_mutex;
bool AgentGuild::s_alive = false;

void AgentGuild::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_guilds.clear();
    s_alive = true;
}

void AgentGuild::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    // Update collective reputation based on member contributions
    for (auto& guild : s_guilds) {
        float totalRep = 0.0f;
        int activeMembers = 0;
        for (const auto& member : guild.members) {
            if (member.isActive) {
                totalRep += member.reputation;
                activeMembers++;
            }
        }
        guild.collectiveReputation = activeMembers > 0 ? totalRep / activeMembers : 0.0f;
    }
}

bool AgentGuild::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

std::string AgentGuild::CreateGuild(const std::string& name, const std::string& purpose) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Guild guild;
    guild.guildId = "guild_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    guild.name = name;
    guild.purpose = purpose;
    guild.collectiveReputation = 0.0f;
    guild.formedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    guild.isActive = true;
    
    s_guilds.push_back(guild);
    return guild.guildId;
}

bool AgentGuild::JoinGuild(const std::string& guildId, const std::string& agentId, const std::string& role) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Guild* guild = FindGuild(guildId);
    if (!guild) return false;
    
    // Check if already member
    if (FindMember(*guild, agentId)) return false;
    
    GuildMember member;
    member.agentId = agentId;
    member.role = role;
    member.reputation = 1.0f;
    member.joinedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    member.contributions = 0;
    member.isActive = true;
    
    guild->members.push_back(member);
    return true;
}

bool AgentGuild::LeaveGuild(const std::string& guildId, const std::string& agentId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Guild* guild = FindGuild(guildId);
    if (!guild) return false;
    
    auto it = std::remove_if(guild->members.begin(), guild->members.end(),
        [&agentId](const GuildMember& m) { return m.agentId == agentId; });
    
    if (it != guild->members.end()) {
        guild->members.erase(it, guild->members.end());
        return true;
    }
    return false;
}

bool AgentGuild::AssignRole(const std::string& guildId, const std::string& agentId, const std::string& role) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Guild* guild = FindGuild(guildId);
    if (!guild) return false;
    
    GuildMember* member = FindMember(*guild, agentId);
    if (!member) return false;
    
    member->role = role;
    return true;
}

void AgentGuild::UpdateReputation(const std::string& guildId, const std::string& agentId, float delta) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Guild* guild = FindGuild(guildId);
    if (!guild) return;
    
    GuildMember* member = FindMember(*guild, agentId);
    if (!member) return;
    
    member->reputation = std::max(0.0f, std::min(10.0f, member->reputation + delta));
}

void AgentGuild::RecordContribution(const std::string& guildId, const std::string& agentId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Guild* guild = FindGuild(guildId);
    if (!guild) return;
    
    GuildMember* member = FindMember(*guild, agentId);
    if (!member) return;
    
    member->contributions++;
    UpdateReputation(guildId, agentId, 0.1f);
}

nlohmann::json AgentGuild::GetGuild(const std::string& guildId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Guild* guild = FindGuild(guildId);
    if (!guild) return nlohmann::json{{"error", "guild not found"}};
    
    nlohmann::json j;
    j["guildId"] = guild->guildId;
    j["name"] = guild->name;
    j["purpose"] = guild->purpose;
    j["collectiveReputation"] = guild->collectiveReputation;
    j["formedAt"] = guild->formedAt;
    j["isActive"] = guild->isActive;
    j["memberCount"] = guild->members.size();
    return j;
}

nlohmann::json AgentGuild::GetGuilds() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json guilds = nlohmann::json::array();
    for (const auto& guild : s_guilds) {
        if (guild.isActive) {
            nlohmann::json j;
            j["guildId"] = guild.guildId;
            j["name"] = guild.name;
            j["purpose"] = guild.purpose;
            j["memberCount"] = guild.members.size();
            j["collectiveReputation"] = guild.collectiveReputation;
            guilds.push_back(j);
        }
    }
    return guilds;
}

nlohmann::json AgentGuild::GetGuildMembers(const std::string& guildId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    Guild* guild = FindGuild(guildId);
    if (!guild) return nlohmann::json{{"error", "guild not found"}};
    
    nlohmann::json members = nlohmann::json::array();
    for (const auto& member : guild->members) {
        nlohmann::json j;
        j["agentId"] = member.agentId;
        j["role"] = member.role;
        j["reputation"] = member.reputation;
        j["joinedAt"] = member.joinedAt;
        j["contributions"] = member.contributions;
        j["isActive"] = member.isActive;
        members.push_back(j);
    }
    return members;
}

nlohmann::json AgentGuild::GetAgentGuilds(const std::string& agentId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json guilds = nlohmann::json::array();
    for (const auto& guild : s_guilds) {
        for (const auto& member : guild.members) {
            if (member.agentId == agentId && member.isActive) {
                nlohmann::json j;
                j["guildId"] = guild.guildId;
                j["name"] = guild.name;
                j["role"] = member.role;
                j["reputation"] = member.reputation;
                guilds.push_back(j);
                break;
            }
        }
    }
    return guilds;
}

nlohmann::json AgentGuild::GetGuildMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json metrics;
    metrics["totalGuilds"] = s_guilds.size();
    
    size_t totalMembers = 0;
    float avgReputation = 0.0f;
    for (const auto& guild : s_guilds) {
        totalMembers += guild.members.size();
        avgReputation += guild.collectiveReputation;
    }
    
    metrics["totalMembers"] = totalMembers;
    metrics["averageReputation"] = s_guilds.empty() ? 0.0f : avgReputation / s_guilds.size();
    return metrics;
}

nlohmann::json AgentGuild::GetSocietyMetrics() {
    return GetGuildMetrics();
}

Guild* AgentGuild::FindGuild(const std::string& guildId) {
    for (auto& guild : s_guilds) {
        if (guild.guildId == guildId) return &guild;
    }
    return nullptr;
}

GuildMember* AgentGuild::FindMember(Guild& guild, const std::string& agentId) {
    for (auto& member : guild.members) {
        if (member.agentId == agentId) return &member;
    }
    return nullptr;
}

} // namespace Society
} // namespace Sovereign
} // namespace RawrXD
