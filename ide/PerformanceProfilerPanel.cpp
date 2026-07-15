#include "ide/PerformanceProfilerPanel.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "ide/PanelState.hpp"
#include "sovereign/SovereignTelemetry.hpp"
#include <imgui.h>

static bool visible = false;

const char* PerformanceProfilerPanel::Id() { return "PerformanceProfilerPanel"; }
void PerformanceProfilerPanel::Toggle() { PanelState::Toggle(Id()); }
bool PerformanceProfilerPanel::IsWired() { return SubsystemStatus::AlwaysWired(); }

void PerformanceProfilerPanel::Init() {
    PanelState::Register(Id());
}

void PerformanceProfilerPanel::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Performance Profiler", &visible);

    auto t = Telemetry::Collect();

    ImGui::Text("GPU Latency: %llu us", t.GpuLatencyUs);
    ImGui::ProgressBar(t.GpuLatencyUs / 10000.0f, ImVec2(200, 20));
    
    ImGui::Text("KV Pressure: %.2f", t.KvPressure);
    ImGui::ProgressBar(t.KvPressure, ImVec2(200, 20));
    
    ImGui::Text("MoE Load: %.2f", t.MoeLoad);
    ImGui::ProgressBar(t.MoeLoad, ImVec2(200, 20));
    
    ImGui::Text("Bandwidth: %.2f", t.Bandwidth);
    ImGui::ProgressBar(t.Bandwidth, ImVec2(200, 20));
    
    ImGui::Text("Consensus Stability: %.2f", t.ConsensusStability);
    ImGui::ProgressBar(t.ConsensusStability, ImVec2(200, 20));
    
    ImGui::Text("Agent Pressure: %.2f", t.AgentPressure);
    ImGui::ProgressBar(t.AgentPressure, ImVec2(200, 20));

    ImGui::Separator();
    ImGui::Text("Frame Time: %.2f ms", ImGui::GetIO().DeltaTime * 1000.0f);

    ImGui::End();
}
