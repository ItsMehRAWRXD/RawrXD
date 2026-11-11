// ============================================================================
// AgentMarketplace.cpp - Agent Communication & Marketplace Implementation
// ============================================================================

#include "AgentMarketplace.hpp"
#include <algorithm>
#include <iostream>

namespace Sovereign {

AgentMarketplace::AgentMarketplace() = default;
AgentMarketplace::~AgentMarketplace() = default;

bool AgentMarketplace::Initialize() {
    // Add default listings
    AgentListing planner;
    planner.id = "sovereign.planner";
    planner.name = "Planner Agent";
    planner.version = "1.0.0";
    planner.author = "Sovereign";
    planner.description = "Decomposes goals into executable action plans";
    planner.capabilities = {"plan", "decompose", "schedule"};
    planner.isOfficial = true;
    listings_[planner.id] = planner;

    AgentListing reviewer;
    reviewer.id = "sovereign.reviewer";
    reviewer.name = "Code Reviewer";
    reviewer.version = "1.0.0";
    reviewer.author = "Sovereign";
    reviewer.description = "Automated code review with static analysis";
    reviewer.capabilities = {"review", "audit", "lint"};
    reviewer.isOfficial = true;
    listings_[reviewer.id] = reviewer;

    AgentListing builder;
    builder.id = "sovereign.builder";
    builder.name = "Build Agent";
    builder.version = "1.0.0";
    builder.author = "Sovereign";
    builder.description = "Autonomous build and repair agent";
    builder.capabilities = {"build", "compile", "repair"};
    builder.isOfficial = true;
    listings_[builder.id] = builder;

    stats_.totalListings = listings_.size();
    return true;
}

void AgentMarketplace::Shutdown() { listings_.clear(); messages_.clear(); }

std::vector<AgentListing> AgentMarketplace::Search(const std::string& query) {
    std::vector<AgentListing> results;
    std::string lower = query;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    for (const auto& [id, listing] : listings_) {
        std::string nameLower = listing.name;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
        if (nameLower.find(lower) != std::string::npos) {
            results.push_back(listing);
        }
    }
    return results;
}

AgentListing AgentMarketplace::GetListing(const std::string& id) {
    auto it = listings_.find(id);
    if (it != listings_.end()) return it->second;
    return {};
}

bool AgentMarketplace::Install(const std::string& id) {
    auto it = listings_.find(id);
    if (it == listings_.end()) return false;
    it->second.isInstalled = true;
    stats_.totalInstalls++;
    return true;
}

bool AgentMarketplace::Uninstall(const std::string& id) {
    auto it = listings_.find(id);
    if (it == listings_.end()) return false;
    it->second.isInstalled = false;
    return true;
}

bool AgentMarketplace::SendMessage(const AgentMessage& msg) {
    messages_.push_back(msg);
    stats_.totalMessages++;
    return true;
}

bool AgentMarketplace::BroadcastMessage(const AgentMessage& msg) {
    for (const auto& [id, listing] : listings_) {
        if (listing.isInstalled && id != msg.fromAgent) {
            AgentMessage m = msg;
            m.toAgent = id;
            messages_.push_back(m);
            stats_.totalMessages++;
        }
    }
    return true;
}

std::vector<AgentMessage> AgentMarketplace::GetMessages(const std::string& agentId) {
    std::vector<AgentMessage> agentMessages;
    for (const auto& msg : messages_) {
        if (msg.toAgent == agentId || msg.fromAgent == agentId) {
            agentMessages.push_back(msg);
        }
    }
    return agentMessages;
}

} // namespace Sovereign
