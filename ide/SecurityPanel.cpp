#include "ide/SecurityPanel.hpp"
#include "ide/PanelState.hpp"
#include "security/ThreatDetector.hpp"
#include "security/IntrusionPrevention.hpp"
#include <imgui.h>
#include <cstring>

static char threatTypeBuffer[64] = "";
static char sourceBuffer[64] = "";

const char* SecurityPanel::Id() { return "SecurityPanel"; }
void SecurityPanel::Toggle() { PanelState::Toggle(Id()); }
bool SecurityPanel::IsWired() { return true; }
void SecurityPanel::Init() {}

void SecurityPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Security & Threat Detection");

    // Security Overview
    auto metrics = ThreatDetector::GetSecurityMetrics();
    float securityScore = metrics.value("security_score", 0.0);
    
    ImGui::Text("Security Score: %.1f%%", securityScore);
    ImGui::ProgressBar(securityScore / 100.0f, ImVec2(-1, 0), "Security Health");
    
    ImGui::Separator();
    
    // Threat Detection
    if (ImGui::CollapsingHeader("Threat Detection", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Text("Active Threats: %zu", metrics.value("active_threats", 0).get<size_t>());
        ImGui::Text("Critical: %zu", metrics.value("critical_threats", 0).get<size_t>());
        ImGui::Text("High: %zu", metrics.value("high_threats", 0).get<size_t>());
        
        ImGui::InputText("Threat Type", threatTypeBuffer, sizeof(threatTypeBuffer));
        
        if (ImGui::Button("Report Threat")) {
            if (strlen(threatTypeBuffer) > 0) {
                ThreatDetector::ReportThreat(threatTypeBuffer, "medium", nlohmann::json{});
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Detect Threats")) {
            auto threats = ThreatDetector::DetectThreats();
            ImGui::Text("Found %d threats", threats.value("threats_detected", 0).get<int>());
        }
        
        auto activeThreats = ThreatDetector::GetActiveThreats();
        ImGui::Text("Active Threats:");
        ImGui::BeginChild("threats", ImVec2(0, 80), true);
        for (const auto& threat : activeThreats) {
            ImGui::Text("[%s] %s", 
                threat.value("severity", "unknown").c_str(),
                threat.value("type", "unknown").c_str());
        }
        ImGui::EndChild();
    }
    
    ImGui::Separator();
    
    // Intrusion Prevention
    if (ImGui::CollapsingHeader("Intrusion Prevention")) {
        auto preventionMetrics = IntrusionPrevention::GetPreventionMetrics();
        ImGui::Text("Blocked Sources: %zu", preventionMetrics.value("blocked_sources", 0).get<size_t>());
        ImGui::Text("Rate Limited: %zu", preventionMetrics.value("rate_limited_sources", 0).get<size_t>());
        ImGui::Text("Blocked Requests: %zu", preventionMetrics.value("blocked_requests", 0).get<size_t>());
        
        ImGui::InputText("Source", sourceBuffer, sizeof(sourceBuffer));
        
        if (ImGui::Button("Block Source")) {
            if (strlen(sourceBuffer) > 0) {
                IntrusionPrevention::BlockSource(sourceBuffer);
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Unblock")) {
            if (strlen(sourceBuffer) > 0) {
                IntrusionPrevention::UnblockSource(sourceBuffer);
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Check Status")) {
            if (strlen(sourceBuffer) > 0) {
                auto status = IntrusionPrevention::GetRateLimitStatus(sourceBuffer);
                ImGui::Text("Requests: %d", status.value("request_count", 0).get<int>());
            }
        }
    }
    
    ImGui::End();
}
