#include "ide/SocialPanel.hpp"
#include "ide/PanelState.hpp"
#include "social/AgentCollaboration.hpp"
#include "social/KnowledgeSharing.hpp"
#include "social/ConsensusBuilding.hpp"
#include <imgui.h>
#include <cstring>

static char agentIdBuffer[64] = "";
static char taskIdBuffer[64] = "";
static char proposalIdBuffer[64] = "";

const char* SocialPanel::Id() { return "SocialPanel"; }
void SocialPanel::Toggle() { PanelState::Toggle(Id()); }
bool SocialPanel::IsWired() { return true; }
void SocialPanel::Init() {}

void SocialPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Social & Collaboration");

    // Collaboration Metrics
    auto collabMetrics = AgentCollaboration::GetCollaborationMetrics();
    ImGui::Text("Active Agents: %zu / %zu", 
        collabMetrics.value("active_agents", 0).get<size_t>(),
        collabMetrics.value("total_agents", 0).get<size_t>());
    ImGui::Text("Tasks: %zu proposed, %zu accepted, %zu completed",
        collabMetrics.value("tasks_proposed", 0).get<size_t>(),
        collabMetrics.value("tasks_accepted", 0).get<size_t>(),
        collabMetrics.value("tasks_completed", 0).get<size_t>());
    
    ImGui::Separator();
    
    // Agent Registration
    if (ImGui::CollapsingHeader("Agent Management")) {
        ImGui::InputText("Agent ID", agentIdBuffer, sizeof(agentIdBuffer));
        if (ImGui::Button("Register Agent")) {
            if (strlen(agentIdBuffer) > 0) {
                AgentCollaboration::RegisterAgent(agentIdBuffer, {{"type", "generic"}});
                agentIdBuffer[0] = '\0';
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Unregister")) {
            if (strlen(agentIdBuffer) > 0) {
                AgentCollaboration::UnregisterAgent(agentIdBuffer);
                agentIdBuffer[0] = '\0';
            }
        }
        
        // Show registered agents
        auto agents = AgentCollaboration::GetRegisteredAgents();
        ImGui::Text("Registered Agents (%zu):", agents.size());
        ImGui::BeginChild("agents", ImVec2(0, 100), true);
        for (const auto& agent : agents) {
            ImGui::Text("- %s", agent.value("id", "unknown").c_str());
        }
        ImGui::EndChild();
    }
    
    ImGui::Separator();
    
    // Knowledge Sharing
    if (ImGui::CollapsingHeader("Knowledge Sharing")) {
        auto shareMetrics = KnowledgeSharing::GetSharingMetrics();
        ImGui::Text("Shares: %zu", shareMetrics.value("shares", 0).get<size_t>());
        ImGui::Text("Requests: %zu", shareMetrics.value("requests", 0).get<size_t>());
        ImGui::Text("Pool Size: %zu", shareMetrics.value("pool_size", 0).get<size_t>());
        
        if (ImGui::Button("Contribute Knowledge")) {
            KnowledgeSharing::ContributeToPool({{"type", "observation"}, {"value", "new_data"}});
        }
        
        if (ImGui::Button("View Knowledge Pool")) {
            auto pool = KnowledgeSharing::GetKnowledgePool();
            // Would display in a separate window
        }
    }
    
    ImGui::Separator();
    
    // Consensus Building
    if (ImGui::CollapsingHeader("Consensus Building")) {
        auto consensusMetrics = ConsensusBuilding::GetConsensusMetrics();
        ImGui::Text("Proposals: %zu voting, %zu accepted, %zu rejected",
            consensusMetrics.value("proposals_voting", 0).get<size_t>(),
            consensusMetrics.value("proposals_accepted", 0).get<size_t>(),
            consensusMetrics.value("proposals_rejected", 0).get<size_t>());
        ImGui::Text("Success Rate: %.1f%%", 
            consensusMetrics.value("success_rate", 0.0).get<double>() * 100);
        
        ImGui::InputText("Proposal ID", proposalIdBuffer, sizeof(proposalIdBuffer));
        if (ImGui::Button("Create Proposal")) {
            if (strlen(proposalIdBuffer) > 0) {
                ConsensusBuilding::Propose(proposalIdBuffer, {{"action", "test"}});
                proposalIdBuffer[0] = '\0';
            }
        }
        
        // Show active proposals
        auto proposals = ConsensusBuilding::GetAllProposals();
        ImGui::Text("Active Proposals:");
        ImGui::BeginChild("proposals", ImVec2(0, 100), true);
        for (const auto& proposal : proposals) {
            std::string status = proposal.value("status", "unknown");
            ImVec4 color = status == "accepted" ? ImVec4(0, 1, 0, 1) : 
                          status == "rejected" ? ImVec4(1, 0, 0, 1) : 
                          ImVec4(1, 1, 0, 1);
            ImGui::TextColored(color, "- %s [%s]", 
                proposal.value("id", "unknown").c_str(),
                status.c_str());
        }
        ImGui::EndChild();
    }
    
    ImGui::End();
}
