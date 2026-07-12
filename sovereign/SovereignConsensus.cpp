#include "sovereign/SovereignConsensus.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/Beaconism.hpp"
#include <mutex>
#include <algorithm>

namespace SovereignConsensus {
    static std::mutex g_mutex;
    static std::map<uint64_t, Proposal> g_proposals;
    static std::vector<ConsensusResult> g_decisions;
    static ProposalCallback g_proposalCb;
    static ConsensusCallback g_consensusCb;
    static uint32_t g_nodeCount = 1;
    static uint64_t g_nextProposalId = 1;
    static bool g_initialized = false;

    void Init(uint32_t nodeCount) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_nodeCount = std::max(1u, nodeCount);
        g_initialized = true;

        Fabric::Instance().RegisterHandler("consensus_propose", OnFabricMessage);
        Fabric::Instance().RegisterHandler("consensus_vote", OnFabricMessage);
        Fabric::Instance().RegisterHandler("consensus_result", OnFabricMessage);

        Beaconism::Emit(Beaconism::BEACON_ConsensusInit, {
            {"node_count", g_nodeCount},
            {"quorum", static_cast<uint32_t>(g_nodeCount * 0.66f + 1)}
        });
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_initialized = false;
    }

    uint64_t Propose(ProposalType type, const nlohmann::json& payload, uint64_t timeoutMs) {
        std::lock_guard<std::mutex> lock(g_mutex);
        uint64_t id = g_nextProposalId++;

        Proposal proposal;
        proposal.id = id;
        proposal.type = type;
        proposal.payload = payload;
        proposal.proposer = Fabric::Instance().GetNodeId();
        proposal.proposedAt = Beaconism::GetTimestamp();
        proposal.expiresAt = proposal.proposedAt + timeoutMs;
        proposal.quorumThreshold = 0.66f;
        proposal.votes[proposal.proposer] = Vote::YES;

        g_proposals[id] = proposal;

        nlohmann::json msg = {
            {"type", "consensus_propose"},
            {"proposal_id", id},
            {"proposal_type", static_cast<int>(type)},
            {"payload", payload},
            {"proposer", proposal.proposer},
            {"expires", proposal.expiresAt},
            {"timestamp", proposal.proposedAt}
        };
        Fabric::Instance().BroadcastJSON(msg);

        if (g_proposalCb) g_proposalCb(proposal);

        Beaconism::Emit(Beaconism::BEACON_ProposalCreated, {
            {"proposal_id", id},
            {"type", static_cast<int>(type)},
            {"proposer", proposal.proposer}
        });

        return id;
    }

    void VoteOn(uint64_t proposalId, Vote vote) {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_proposals.find(proposalId);
        if (it == g_proposals.end()) return;

        it->second.votes[Fabric::Instance().GetNodeId()] = vote;

        nlohmann::json msg = {
            {"type", "consensus_vote"},
            {"proposal_id", proposalId},
            {"voter", Fabric::Instance().GetNodeId()},
            {"vote", static_cast<int>(vote)},
            {"timestamp", Beaconism::GetTimestamp()}
        };
        Fabric::Instance().BroadcastJSON(msg);

        Beaconism::Emit(Beaconism::BEACON_VoteCast, {
            {"proposal_id", proposalId},
            {"voter", Fabric::Instance().GetNodeId()},
            {"vote", static_cast<int>(vote)}
        });

        if (IsQuorumReached(it->second)) {
            CheckConsensus(proposalId);
        }
    }

    void RegisterProposalCallback(ProposalCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_proposalCb = cb;
    }

    void RegisterConsensusCallback(ConsensusCallback cb) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_consensusCb = cb;
    }

    std::vector<Proposal> GetActiveProposals() {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::vector<Proposal> result;
        uint64_t now = Beaconism::GetTimestamp();
        for (const auto& [id, proposal] : g_proposals) {
            if (proposal.expiresAt > now) {
                result.push_back(proposal);
            }
        }
        return result;
    }

    std::vector<ConsensusResult> GetDecisionHistory() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_decisions;
    }

    bool IsQuorumReached(const Proposal& proposal) {
        uint32_t yesVotes = 0;
        uint32_t totalVotes = 0;
        for (const auto& [voter, vote] : proposal.votes) {
            if (vote == Vote::YES) yesVotes++;
            if (vote != Vote::PENDING) totalVotes++;
        }
        float ratio = static_cast<float>(yesVotes) / std::max(1u, g_nodeCount);
        return ratio >= proposal.quorumThreshold;
    }

    ConsensusResult CheckConsensus(uint64_t proposalId) {
        std::lock_guard<std::mutex> lock(g_mutex);
        ConsensusResult result;
        result.proposalId = proposalId;
        result.decidedAt = Beaconism::GetTimestamp();

        auto it = g_proposals.find(proposalId);
        if (it == g_proposals.end()) return result;

        uint32_t yesVotes = 0;
        uint32_t noVotes = 0;
        for (const auto& [voter, vote] : it->second.votes) {
            if (vote == Vote::YES) yesVotes++;
            if (vote == Vote::NO) noVotes++;
        }

        result.yesRatio = static_cast<float>(yesVotes) / std::max(1u, g_nodeCount);
        result.accepted = result.yesRatio >= it->second.quorumThreshold;
        result.executor = it->second.proposer;

        g_decisions.push_back(result);
        g_proposals.erase(it);

        if (g_consensusCb) g_consensusCb(result);

        nlohmann::json msg = {
            {"type", "consensus_result"},
            {"proposal_id", proposalId},
            {"accepted", result.accepted},
            {"yes_ratio", result.yesRatio},
            {"executor", result.executor}
        };
        Fabric::Instance().BroadcastJSON(msg);

        Beaconism::Emit(Beaconism::BEACON_ConsensusReached, {
            {"proposal_id", proposalId},
            {"accepted", result.accepted},
            {"yes_ratio", result.yesRatio}
        });

        return result;
    }

    void OnFabricMessage(const nlohmann::json& msg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        std::string type = msg.value("type", "");

        if (type == "consensus_propose") {
            uint64_t id = msg.value("proposal_id", 0ULL);
            if (g_proposals.find(id) == g_proposals.end()) {
                Proposal proposal;
                proposal.id = id;
                proposal.type = static_cast<ProposalType>(msg.value("proposal_type", 0));
                proposal.payload = msg.value("payload", nlohmann::json::object());
                proposal.proposer = msg.value("proposer", "");
                proposal.proposedAt = msg.value("timestamp", 0ULL);
                proposal.expiresAt = msg.value("expires", 0ULL);
                g_proposals[id] = proposal;

                if (g_proposalCb) g_proposalCb(proposal);
            }
        }
        else if (type == "consensus_vote") {
            uint64_t id = msg.value("proposal_id", 0ULL);
            auto it = g_proposals.find(id);
            if (it != g_proposals.end()) {
                std::string voter = msg.value("voter", "");
                Vote vote = static_cast<Vote>(msg.value("vote", 0));
                it->second.votes[voter] = vote;

                if (IsQuorumReached(it->second)) {
                    CheckConsensus(id);
                }
            }
        }
        else if (type == "consensus_result") {
            Beaconism::Emit(Beaconism::BEACON_ConsensusResultRemote, {
                {"proposal_id", msg.value("proposal_id", 0ULL)},
                {"accepted", msg.value("accepted", false)},
                {"yes_ratio", msg.value("yes_ratio", 0.0f)}
            });
        }
    }

    bool SovereignConsensus::IsReady() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_initialized;
    }

    // Alias for audit compatibility
    ConsensusResult SovereignConsensus::ProposeAndVote(ProposalType type, const nlohmann::json& payload, uint64_t timeoutMs) {
        uint64_t id = Propose(type, payload, timeoutMs);
        return CheckConsensus(id);
    }
}
