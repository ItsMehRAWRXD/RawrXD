#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Society {

struct GuildMember {
    std::string agentId;
    std::string role;
    float reputation;
    int64_t joinedAt;
    int contributions;
    bool isActive;
};

struct Guild {
    std::string guildId;
    std::string name;
    std::string purpose;
    std::vector<GuildMember> members;
    std::map<std::string, std::string> norms;
    float collectiveReputation;
    int64_t formedAt;
    bool isActive;
};

class AgentGuild {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();

    static std::string CreateGuild(const std::string& name, const std::string& purpose);
    static bool JoinGuild(const std::string& guildId, const std::string& agentId, const std::string& role);
    static bool LeaveGuild(const std::string& guildId, const std::string& agentId);
    static bool AssignRole(const std::string& guildId, const std::string& agentId, const std::string& role);
    
    static void UpdateReputation(const std::string& guildId, const std::string& agentId, float delta);
    static void RecordContribution(const std::string& guildId, const std::string& agentId);
    
    static nlohmann::json GetGuild(const std::string& guildId);
    static nlohmann::json GetGuilds();
    static nlohmann::json GetGuildMembers(const std::string& guildId);
    static nlohmann::json GetAgentGuilds(const std::string& agentId);
    
    static nlohmann::json GetGuildMetrics();
    static nlohmann::json GetSocietyMetrics();

private:
    static std::vector<Guild> s_guilds;
    static std::mutex s_mutex;
    static bool s_alive;
    
    static Guild* FindGuild(const std::string& guildId);
    static GuildMember* FindMember(Guild& guild, const std::string& agentId);
};

} // namespace Society
} // namespace Sovereign
} // namespace RawrXD
