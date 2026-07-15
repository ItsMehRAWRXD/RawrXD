#include "social/ConsensusBuilding.hpp"
#include <mutex>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::map<std::string, nlohmann::json> s_proposals;

void ConsensusBuilding::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_proposals.clear();
        s_initialized = true;
    }
}

void ConsensusBuilding::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Check for consensus on pending proposals
    for (auto& [id, proposal] : s_proposals) {
        if (proposal.value("status", "") == "voting") {
            auto votes = proposal.value("votes", nlohmann::json::object());
            size_t approvals = 0;
            size_t rejections = 0;
            size_t abstentions = 0;
            
            for (const auto& [agent, vote] : votes.items()) {
                if (vote == "approve") approvals++;
                else if (vote == "reject") rejections++;
                else if (vote == "abstain") abstentions++;
            }
            
            size_t total = approvals + rejections + abstentions;
            if (total > 0) {
                double approvalRate = approvals / static_cast<double>(total);
                if (approvalRate >= 0.67) { // 2/3 majority
                    proposal["status"] = "accepted";
                    proposal["consensus_reached_at"] = std::chrono::system_clock::now().time_since_epoch().count();
                } else if (rejections / static_cast<double>(total) > 0.33) {
                    proposal["status"] = "rejected";
                }
            }
        }
    }
}

bool ConsensusBuilding::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void ConsensusBuilding::Propose(const std::string& proposalId, const nlohmann::json& proposal) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_proposals[proposalId] = {
        {"id", proposalId},
        {"proposal", proposal},
        {"status", "voting"},
        {"proposed_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"votes", nlohmann::json::object()}
    };
}

void ConsensusBuilding::Vote(const std::string& proposalId, const std::string& agentId, bool approve) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_proposals.find(proposalId);
    if (it != s_proposals.end()) {
        it->second["votes"][agentId] = approve ? "approve" : "reject";
        it->second["votes"][agentId + "_time"] = std::chrono::system_clock::now().time_since_epoch().count();
    }
}

void ConsensusBuilding::Abstain(const std::string& proposalId, const std::string& agentId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_proposals.find(proposalId);
    if (it != s_proposals.end()) {
        it->second["votes"][agentId] = "abstain";
    }
}

nlohmann::json ConsensusBuilding::GetProposalStatus(const std::string& proposalId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_proposals.find(proposalId);
    if (it != s_proposals.end()) {
        return it->second;
    }
    return nlohmann::json{};
}

nlohmann::json ConsensusBuilding::GetAllProposals() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [id, proposal] : s_proposals) {
        result.push_back(proposal);
    }
    return result;
}

bool ConsensusBuilding::IsConsensusReached(const std::string& proposalId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_proposals.find(proposalId);
    if (it != s_proposals.end()) {
        return it->second.value("status", "") == "accepted";
    }
    return false;
}

nlohmann::json ConsensusBuilding::GetConsensusMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t voting = 0, accepted = 0, rejected = 0;
    for (const auto& [id, proposal] : s_proposals) {
        std::string status = proposal.value("status", "");
        if (status == "voting") voting++;
        else if (status == "accepted") accepted++;
        else if (status == "rejected") rejected++;
    }
    
    return {
        {"proposals_voting", voting},
        {"proposals_accepted", accepted},
        {"proposals_rejected", rejected},
        {"total_proposals", s_proposals.size()},
        {"success_rate", s_proposals.size() > 0 ? (accepted / static_cast<double>(s_proposals.size())) : 0.0}
    };
}
