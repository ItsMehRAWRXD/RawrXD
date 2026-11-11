// Phase V.4/5: Multi-Agent Cognitive Coordination
// RawrXD Multi-Agent Coordination - Coordinated reasoning across multiple agents

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace MetaCognition {

// Agent role types
enum class AgentRole {
    PLANNER,        // Strategic planning
    CODER,          // Code generation
    ANALYST,        // Analysis and evaluation
    TESTER,         // Testing and validation
    SECURITY,       // Security assessment
    OPTIMIZER,      // Performance optimization
    REVIEWER,       // Code review
    DEBUGGER        // Debugging specialist
};

// Agent descriptor
struct AgentDescriptor {
    std::string agent_id;
    std::string name;
    AgentRole role;
    
    // Capabilities
    std::vector<std::string> capabilities;
    std::vector<std::string> specializations;
    double competence_score;
    
    // State
    bool is_available;
    std::string current_task;
    std::chrono::system_clock::time_point last_active;
    
    // Performance
    uint32_t tasks_completed;
    uint32_t tasks_failed;
    double success_rate;
    double average_task_duration_ms;
};

// Consensus proposal
struct ConsensusProposal {
    std::string proposal_id;
    std::string topic;
    std::string proposed_solution;
    std::string proposing_agent;
    std::chrono::system_clock::time_point proposed_at;
    
    // Reasoning
    std::string reasoning;
    std::vector<std::string> supporting_evidence;
    double confidence;
    
    // Votes
    struct Vote {
        std::string agent_id;
        bool approve;
        double confidence;
        std::string reasoning;
        std::chrono::system_clock::time_point voted_at;
    };
    std::vector<Vote> votes;
    
    // Status
    enum class Status {
        PENDING,
        VOTING,
        APPROVED,
        REJECTED,
        EXPIRED
    } status;
    
    double consensus_level;
    uint32_t required_votes;
};

// Disagreement record
struct Disagreement {
    std::string disagreement_id;
    std::string topic;
    std::chrono::system_clock::time_point occurred_at;
    
    // Positions
    struct Position {
        std::string agent_id;
        std::string position;
        std::string reasoning;
        double confidence;
    };
    std::vector<Position> positions;
    
    // Resolution
    bool is_resolved;
    std::string resolution;
    std::string winning_position;
    std::string resolution_method;  // "consensus", "arbitration", "evidence"
};

// Arbitration request
struct ArbitrationRequest {
    std::string request_id;
    std::string disagreement_id;
    std::string requesting_agent;
    std::chrono::system_clock::time_point requested_at;
    
    // Context
    std::string issue_description;
    std::vector<std::string> conflicting_opinions;
    std::vector<std::string> relevant_evidence;
    
    // Decision criteria
    std::vector<std::string> decision_criteria;
    double required_confidence;
};

// Multi-agent coordination interface
class IMultiAgentCoordination {
public:
    virtual ~IMultiAgentCoordination() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Agent management
    virtual std::string RegisterAgent(const AgentDescriptor& agent) = 0;
    virtual bool UnregisterAgent(const std::string& agent_id) = 0;
    virtual bool UpdateAgent(const AgentDescriptor& agent) = 0;
    virtual std::optional<AgentDescriptor> GetAgent(const std::string& agent_id) = 0;
    virtual std::vector<AgentDescriptor> ListAgents() = 0;
    virtual std::vector<AgentDescriptor> GetAgentsByRole(AgentRole role) = 0;
    virtual std::vector<AgentDescriptor> GetAvailableAgents() = 0;
    
    // Task assignment
    virtual std::string AssignTask(const std::string& task_type, 
                                    const std::unordered_map<std::string, std::string>& requirements) = 0;
    virtual bool ReassignTask(const std::string& task_id, const std::string& new_agent_id) = 0;
    virtual std::optional<std::string> SelectBestAgent(const std::string& task_type,
                                                          const std::vector<std::string>& candidate_agents) = 0;
    
    // Consensus building
    virtual std::string ProposeConsensus(const std::string& topic,
                                          const std::string& proposal,
                                          const std::string& proposing_agent) = 0;
    virtual bool VoteOnProposal(const std::string& proposal_id,
                                 const std::string& agent_id,
                                 bool approve,
                                 double confidence,
                                 const std::string& reasoning) = 0;
    virtual std::optional<ConsensusProposal> GetProposal(const std::string& proposal_id) = 0;
    virtual double CalculateConsensusLevel(const std::string& proposal_id) = 0;
    virtual bool HasConsensus(const std::string& proposal_id, double threshold = 0.7) = 0;
    
    // Disagreement handling
    virtual std::string RecordDisagreement(const std::string& topic,
                                            const std::vector<std::string>& agent_positions) = 0;
    virtual bool ResolveDisagreement(const std::string& disagreement_id,
                                    const std::string& resolution,
                                    const std::string& method) = 0;
    virtual std::vector<Disagreement> GetActiveDisagreements() = 0;
    
    // Arbitration
    virtual std::string RequestArbitration(const std::string& disagreement_id,
                                             const std::string& requesting_agent) = 0;
    virtual std::string Arbitrate(const std::string& request_id,
                                   const std::vector<std::string>& evidence) = 0;
    virtual std::optional<ArbitrationRequest> GetArbitrationRequest(const std::string& request_id) = 0;
    
    // Evidence sharing
    virtual bool ShareEvidence(const std::string& from_agent,
                                const std::string& to_agent,
                                const std::string& evidence) = 0;
    virtual std::vector<std::string> GetSharedEvidence(const std::string& agent_id) = 0;
    
    // Coordination statistics
    virtual struct CoordinationStatistics {
        uint32_t registered_agents;
        uint32_t active_agents;
        uint64_t tasks_assigned;
        uint64_t tasks_completed;
        uint32_t proposals_made;
        uint32_t proposals_approved;
        uint32_t disagreements_recorded;
        uint32_t disagreements_resolved;
        uint32_t arbitrations_requested;
        double average_consensus_time_ms;
        double average_arbitration_time_ms;
    } GetStatistics() = 0;
};

// Local multi-agent coordination
class LocalMultiAgentCoordination : public IMultiAgentCoordination {
public:
    LocalMultiAgentCoordination();
    ~LocalMultiAgentCoordination() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string RegisterAgent(const AgentDescriptor& agent) override;
    bool UnregisterAgent(const std::string& agent_id) override;
    bool UpdateAgent(const AgentDescriptor& agent) override;
    std::optional<AgentDescriptor> GetAgent(const std::string& agent_id) override;
    std::vector<AgentDescriptor> ListAgents() override;
    std::vector<AgentDescriptor> GetAgentsByRole(AgentRole role) override;
    std::vector<AgentDescriptor> GetAvailableAgents() override;
    
    std::string AssignTask(const std::string& task_type, 
                           const std::unordered_map<std::string, std::string>& requirements) override;
    bool ReassignTask(const std::string& task_id, const std::string& new_agent_id) override;
    std::optional<std::string> SelectBestAgent(const std::string& task_type,
                                                  const std::vector<std::string>& candidate_agents) override;
    
    std::string ProposeConsensus(const std::string& topic,
                                  const std::string& proposal,
                                  const std::string& proposing_agent) override;
    bool VoteOnProposal(const std::string& proposal_id,
                         const std::string& agent_id,
                         bool approve,
                         double confidence,
                         const std::string& reasoning) override;
    std::optional<ConsensusProposal> GetProposal(const std::string& proposal_id) override;
    double CalculateConsensusLevel(const std::string& proposal_id) override;
    bool HasConsensus(const std::string& proposal_id, double threshold = 0.7) override;
    
    std::string RecordDisagreement(const std::string& topic,
                                    const std::vector<std::string>& agent_positions) override;
    bool ResolveDisagreement(const std::string& disagreement_id,
                              const std::string& resolution,
                              const std::string& method) override;
    std::vector<Disagreement> GetActiveDisagreements() override;
    
    std::string RequestArbitration(const std::string& disagreement_id,
                                    const std::string& requesting_agent) override;
    std::string Arbitrate(const std::string& request_id,
                          const std::vector<std::string>& evidence) override;
    std::optional<ArbitrationRequest> GetArbitrationRequest(const std::string& request_id) override;
    
    bool ShareEvidence(const std::string& from_agent,
                        const std::string& to_agent,
                        const std::string& evidence) override;
    std::vector<std::string> GetSharedEvidence(const std::string& agent_id) override;
    
    CoordinationStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, AgentDescriptor> agents_;
    std::unordered_map<std::string, ConsensusProposal> proposals_;
    std::unordered_map<std::string, Disagreement> disagreements_;
    std::unordered_map<std::string, ArbitrationRequest> arbitrations_;
    bool initialized_ = false;
    
    double CalculateAgentScore(const AgentDescriptor& agent, const std::string& task_type);
    void UpdateConsensusLevel(const std::string& proposal_id);
    std::string ResolveByEvidence(const ArbitrationRequest& request);
    std::string ResolveByCompromise(const Disagreement& disagreement);
};

// Global multi-agent coordination
extern std::unique_ptr<IMultiAgentCoordination> g_multi_agent_coordination;

// Initialize multi-agent coordination
bool InitializeMultiAgentCoordination(const std::string& config_path);
void ShutdownMultiAgentCoordination();
bool IsMultiAgentCoordinationEnabled();

// Agent role helpers
std::string AgentRoleToString(AgentRole role);
AgentRole AgentRoleFromString(const std::string& str);

} // namespace MetaCognition
} // namespace RawrXD
