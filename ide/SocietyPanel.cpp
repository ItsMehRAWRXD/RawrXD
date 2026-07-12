#include "ide/SocietyPanel.hpp"
#include "imgui.h"
#include "society/AgentGuild.hpp"
#include "society/SocialContract.hpp"
#include "society/AgentNegotiation.hpp"
#include "society/SocietyLoop.hpp"
#include "ide/PanelState.hpp"

namespace RawrXD {
namespace IDE {

bool SocietyPanel::s_visible = false;
int SocietyPanel::s_selectedGuild = -1;
int SocietyPanel::s_selectedAgent = -1;
int SocietyPanel::s_selectedContract = -1;
int SocietyPanel::s_selectedSession = -1;

void SocietyPanel::Init() {
    s_visible = false;
    s_selectedGuild = -1;
    s_selectedAgent = -1;
    s_selectedContract = -1;
    s_selectedSession = -1;
}

void SocietyPanel::Render() {
    if (!s_visible) return;

    if (ImGui::Begin("Society", &s_visible)) {
        // Society metrics
        ImGui::Text("Society Metrics");
        auto metrics = Sovereign::Society::SocietyLoop::GetSocietyMetrics();
        
        if (metrics.contains("guilds")) {
            auto guildMetrics = metrics["guilds"];
            ImGui::Text("Guilds: %d", guildMetrics.value("totalGuilds", 0));
            ImGui::Text("Members: %d", guildMetrics.value("totalMembers", 0));
        }
        
        if (metrics.contains("contracts")) {
            auto contractMetrics = metrics["contracts"];
            ImGui::Text("Contracts: %d", contractMetrics.value("totalContracts", 0));
            ImGui::Text("Active: %d", contractMetrics.value("activeContracts", 0));
        }
        
        if (metrics.contains("negotiations")) {
            auto negMetrics = metrics["negotiations"];
            ImGui::Text("Sessions: %d", negMetrics.value("totalSessions", 0));
            ImGui::Text("Success Rate: %.1f%%", negMetrics.value("successRate", 0.0f) * 100);
        }
        
        ImGui::Separator();
        
        // Guilds section
        if (ImGui::CollapsingHeader("Guilds")) {
            auto guilds = Sovereign::Society::AgentGuild::GetGuilds();
            if (guilds.is_array() && !guilds.empty()) {
                for (size_t i = 0; i < guilds.size(); i++) {
                    const auto& guild = guilds[i];
                    std::string label = guild.value("name", "Unnamed") + " [" + 
                                       std::to_string(guild.value("memberCount", 0)) + "]";
                    if (ImGui::Selectable(label.c_str(), s_selectedGuild == (int)i)) {
                        s_selectedGuild = (int)i;
                    }
                }
            } else {
                ImGui::TextDisabled("No guilds");
            }
            
            if (ImGui::Button("Create Guild")) {
                // TODO: Open create guild dialog
            }
        }
        
        // Contracts section
        if (ImGui::CollapsingHeader("Contracts")) {
            auto clauses = Sovereign::Society::SocialContract::GetClauses();
            ImGui::Text("Clauses: %d", (int)clauses.size());
            
            if (ImGui::Button("Create Clause")) {
                // TODO: Open create clause dialog
            }
        }
        
        // Negotiations section
        if (ImGui::CollapsingHeader("Negotiations")) {
            auto negMetrics = Sovereign::Society::AgentNegotiation::GetNegotiationMetrics();
            ImGui::Text("Active Sessions: %d", negMetrics.value("activeSessions", 0));
            ImGui::Text("Honor Rate: %.1f%%", negMetrics.value("honorRate", 0.0f) * 100);
            
            if (ImGui::Button("Start Session")) {
                // TODO: Open start session dialog
            }
        }
        
        ImGui::Separator();
        
        // Tick control
        if (ImGui::Button("Tick Society")) {
            Sovereign::Society::SocietyLoop::OnTick();
        }
        ImGui::SameLine();
        ImGui::Text("Alive: %s", Sovereign::Society::SocietyLoop::IsAlive() ? "Yes" : "No");
    }
    ImGui::End();
}

void SocietyPanel::Toggle() {
    s_visible = !s_visible;
    PanelState::SetVisible(Id(), s_visible);
}

bool SocietyPanel::IsVisible() {
    return s_visible;
}

const char* SocietyPanel::Id() {
    return "SocietyPanel";
}

} // namespace IDE
} // namespace RawrXD
