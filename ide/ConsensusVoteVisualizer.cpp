#include "ide/ConsensusVoteVisualizer.hpp"
#include "ide/PanelState.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include <imgui.h>
#include <vector>
#include <string>
#include <map>

struct Vote {
    std::string voter;
    bool yes;
    uint64_t timestamp;
};

struct Proposal {
    std::string id;
    std::string description;
    std::vector<Vote> votes;
    bool decided;
    bool accepted;
};

static std::vector<Proposal> g_proposals;
static bool visible = false;

const char* ConsensusVoteVisualizer::Id() { return "ConsensusVoteVisualizer"; }
void ConsensusVoteVisualizer::Toggle() { PanelState::Toggle(Id()); }
bool ConsensusVoteVisualizer::IsWired() { return SubsystemStatus::AlwaysWired(); }

void ConsensusVoteVisualizer::Init() {
    PanelState::Register(Id());
}

void ConsensusVoteVisualizer::OnVoteReceived(const char* proposal, const char* voter, bool vote) {
    auto it = std::find_if(g_proposals.begin(), g_proposals.end(),
        [&](const Proposal& p) { return p.id == proposal; });
    
    if (it == g_proposals.end()) {
        Proposal p;
        p.id = proposal;
        p.description = "Proposal " + std::string(proposal);
        p.decided = false;
        p.accepted = false;
        g_proposals.push_back(p);
        it = g_proposals.end() - 1;
    }
    
    Vote v;
    v.voter = voter;
    v.yes = vote;
    v.timestamp = 0;
    it->votes.push_back(v);
}

void ConsensusVoteVisualizer::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Real-Time Consensus Votes", &visible);

    ImGui::Text("Active Proposals: %zu", g_proposals.size());
    ImGui::Separator();

    for (auto& p : g_proposals) {
        int yesVotes = 0;
        int noVotes = 0;
        for (const auto& v : p.votes) {
            if (v.yes) yesVotes++; else noVotes++;
        }
        
        float ratio = (p.votes.size() > 0) ? (float)yesVotes / p.votes.size() : 0.0f;
        
        ImVec4 color = p.decided 
            ? (p.accepted ? ImVec4(0.2f, 1.0f, 0.2f, 1.0f) : ImVec4(1.0f, 0.2f, 0.2f, 1.0f))
            : ImVec4(1.0f, 1.0f, 0.2f, 1.0f);
        
        ImGui::PushStyleColor(ImGuiCol_Text, color);
        
        if (ImGui::CollapsingHeader(p.description.c_str())) {
            ImGui::ProgressBar(ratio, ImVec2(200, 20));
            ImGui::Text("Yes: %d | No: %d | Total: %zu", yesVotes, noVotes, p.votes.size());
            
            ImGui::Text("Voters:");
            for (const auto& v : p.votes) {
                ImVec4 vcolor = v.yes ? ImVec4(0.2f, 1.0f, 0.2f, 1.0f) : ImVec4(1.0f, 0.2f, 0.2f, 1.0f);
                ImGui::TextColored(vcolor, "  %s: %s", v.voter.c_str(), v.yes ? "YES" : "NO");
            }
        }
        
        ImGui::PopStyleColor();
    }

    ImGui::End();
}
