#include "ide/RoutingConfidenceGauge.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "sovereign/SovereignTelemetry.hpp"
#include "ide/PanelState.hpp"
#include <imgui.h>

static bool visible = false;

const char* RoutingConfidenceGauge::Id() { return "RoutingConfidenceGauge"; }
void RoutingConfidenceGauge::Toggle() { PanelState::Toggle(Id()); }
bool RoutingConfidenceGauge::IsWired() { return SubsystemStatus::AlwaysWired(); }

void RoutingConfidenceGauge::Init() {
    PanelState::Register(Id());
}

void RoutingConfidenceGauge::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Routing Confidence Gauge", &visible);

    auto t = Telemetry::Collect();
    float v = t.ConsensusStability;
    if (v < 0.0f) v = 0.0f;
    if (v > 1.0f) v = 1.0f;

    ImVec4 color = v > 0.7f ? ImVec4(0.2f, 1.0f, 0.2f, 1.0f) :
                   v > 0.4f ? ImVec4(1.0f, 1.0f, 0.2f, 1.0f) :
                              ImVec4(1.0f, 0.2f, 0.2f, 1.0f);

    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color);
    ImGui::ProgressBar(v, ImVec2(200, 30));
    ImGui::PopStyleColor();

    ImGui::Text("Confidence: %.1f%%", v * 100.0f);

    ImGui::End();
}
