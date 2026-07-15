#include "ide/IdentityPanel.hpp"
#include "ide/PanelState.hpp"
#include "identity/IdentityModel.hpp"
#include "identity/ContinuityManager.hpp"
#include "identity/GoalPersistence.hpp"
#include "identity/MemoryAlignment.hpp"
#include "identity/IdentityLoop.hpp"
#include "consciousness/SelfModel.hpp"

const char* IdentityPanel::Id() { return "IdentityPanel"; }
void IdentityPanel::Toggle() { PanelState::Toggle(Id()); }
bool IdentityPanel::IsWired() { return true; }
void IdentityPanel::Init() {}

void IdentityPanel::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Identity & Continuity");

    // Identity Hash
    ImGui::Text("Identity Hash:");
    ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "%s", 
        IdentityModel::GetIdentityHash().c_str());
    
    // Core Identity
    ImGui::Separator();
    ImGui::Text("Core Identity:");
    auto identity = IdentityModel::GetCoreIdentity();
    if (identity.contains("purpose")) {
        ImGui::Text("Purpose: %s", identity["purpose"].get<std::string>().c_str());
    }
    if (identity.contains("version")) {
        ImGui::Text("Version: %s", identity["version"].get<std::string>().c_str());
    }
    
    // Continuity Status
    ImGui::Separator();
    ImGui::Text("Continuity Status:");
    std::string status = ContinuityManager::GetContinuityStatus();
    if (status == "continuous") {
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "CONTINUOUS");
    } else if (status == "drifted") {
        ImGui::TextColored(ImVec4(1, 0.5f, 0, 1), "DRIFTED");
    } else {
        ImGui::TextColored(ImVec4(1, 0, 0, 1), "DISCONTINUOUS");
    }
    
    // Memory Alignment
    ImGui::Separator();
    ImGui::Text("Memory Alignment:");
    float alignment = MemoryAlignment::ComputeAlignmentScore();
    ImGui::ProgressBar(alignment);
    if (MemoryAlignment::IsAligned()) {
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "ALIGNED");
    } else {
        ImGui::TextColored(ImVec4(1, 0, 0, 1), "MISALIGNED");
    }
    
    // Persistent Goals
    ImGui::Separator();
    ImGui::Text("Persistent Goals: %zu", GoalPersistence::GetPersistentGoals().size());
    
    // Identity Intact
    ImGui::Separator();
    if (IdentityLoop::IsIdentityIntact()) {
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "IDENTITY INTACT");
    } else {
        ImGui::TextColored(ImVec4(1, 0, 0, 1), "IDENTITY COMPROMISED");
    }

    ImGui::End();
}
