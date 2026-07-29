// ============================================================================
// AgentMarketplace.hpp - Agent Communication & Marketplace
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

struct AgentListing {
    std::string id;
    std::string name;
    std::string version;
    std::string author;
    std::string description;
    std::vector<std::string> capabilities;
    std::string downloadUrl;
    uint64_t downloads;
    float rating;
    bool isInstalled;
    bool isOfficial;
};

struct AgentMessage {
    uint64_t id;
    std::string fromAgent;
    std::string toAgent;
    std::string subject;
    std::string body;
    uint64_t timestamp;
    bool requiresResponse;
    bool isResponse;
    uint64_t responseTo;
};

class AgentMarketplace {
public:
    AgentMarketplace();
    ~AgentMarketplace();

    bool Initialize();
    void Shutdown();

    // Marketplace
    std::vector<AgentListing> Search(const std::string& query);
    AgentListing GetListing(const std::string& id);
    bool Install(const std::string& id);
    bool Uninstall(const std::string& id);
    bool Update(const std::string& id);
    bool Publish(const AgentListing& listing);

    // Agent communication
    bool SendMessage(const AgentMessage& msg);
    bool BroadcastMessage(const AgentMessage& msg);
    std::vector<AgentMessage> GetMessages(const std::string& agentId);
    bool RespondToMessage(uint64_t messageId, const std::string& response);

    struct MarketplaceStats { uint64_t totalListings; uint64_t totalInstalls; uint64_t totalMessages; };
    MarketplaceStats GetStats() const { return stats_; }

private:
    std::unordered_map<std::string, AgentListing> listings_;
    std::vector<AgentMessage> messages_;
    MarketplaceStats stats_;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
