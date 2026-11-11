#include "ide/GovernancePanel.hpp"
#include "ide/PanelState.hpp"
#include "governance/PolicyEnforcer.hpp"
#include "governance/AuditLogger.hpp"
#include <imgui.h>
#include <cstring>

static char policyIdBuffer[64] = "";
static char actorBuffer[64] = "";

const char* GovernancePanel::Id() { return "GovernancePanel"; }
void GovernancePanel::Toggle() { PanelState::Toggle(Id()); }
bool GovernancePanel::IsWired() { return true; }
void GovernancePanel::Init() {}

void GovernancePanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Governance & Compliance");

    // Policy Enforcement
    if (ImGui::CollapsingHeader("Policy Enforcement", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto metrics = PolicyEnforcer::GetPolicyMetrics();
        ImGui::Text("Total Policies: %zu", metrics.value("total_policies", 0).get<size_t>());
        ImGui::Text("Active: %zu", metrics.value("active_policies", 0).get<size_t>());
        ImGui::Text("Evaluations: %zu", metrics.value("evaluations", 0).get<size_t>());
        ImGui::Text("Violations: %zu", metrics.value("violations", 0).get<size_t>());
        
        float violationRate = metrics.value("violation_rate", 0.0);
        ImGui::Text("Violation Rate: %.2f%%", violationRate * 100);
        
        ImGui::InputText("Policy ID", policyIdBuffer, sizeof(policyIdBuffer));
        
        if (ImGui::Button("Get Policy")) {
            if (strlen(policyIdBuffer) > 0) {
                auto policy = PolicyEnforcer::GetPolicy(policyIdBuffer);
                ImGui::Text("Active: %s", policy.value("active", false) ? "yes" : "no");
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("List All")) {
            auto policies = PolicyEnforcer::GetAllPolicies();
            ImGui::Text("Found %zu policies", policies.size());
        }
    }
    
    ImGui::Separator();
    
    // Audit Logging
    if (ImGui::CollapsingHeader("Audit Logging")) {
        auto metrics = AuditLogger::GetAuditMetrics();
        ImGui::Text("Total Events: %zu", metrics.value("total_events", 0).get<size_t>());
        ImGui::Text("Success: %zu", metrics.value("success_count", 0).get<size_t>());
        ImGui::Text("Failure: %zu", metrics.value("failure_count", 0).get<size_t>());
        
        ImGui::InputText("Actor", actorBuffer, sizeof(actorBuffer));
        
        if (ImGui::Button("Log Event")) {
            if (strlen(actorBuffer) > 0) {
                AuditLogger::LogEvent("user_action", actorBuffer, {{"action", "test"}});
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Recent Events")) {
            auto events = AuditLogger::GetRecentEvents(10);
            ImGui::Text("Found %zu events", events.size());
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear Log")) {
            AuditLogger::ClearAuditLog();
        }
        
        auto recentEvents = AuditLogger::GetRecentEvents(5);
        ImGui::Text("Recent Events:");
        ImGui::BeginChild("events", ImVec2(0, 80), true);
        for (const auto& event : recentEvents) {
            ImGui::Text("[%s] %s", 
                event.value("type", "unknown").c_str(),
                event.value("actor", "unknown").c_str());
        }
        ImGui::EndChild();
    }
    
    ImGui::End();
}
