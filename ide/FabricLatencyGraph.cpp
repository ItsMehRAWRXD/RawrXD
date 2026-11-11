#include "ide/FabricLatencyGraph.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "sovereign/SovereignTelemetry.hpp"
#include "ide/PanelState.hpp"
#include <imgui.h>

static float history[256];
static int index = 0;
static bool visible = false;

const char* FabricLatencyGraph::Id() { return "FabricLatencyGraph"; }
void FabricLatencyGraph::Toggle() { PanelState::Toggle(Id()); }
bool FabricLatencyGraph::IsWired() { return SubsystemStatus::AlwaysWired(); }

void FabricLatencyGraph::Init() {
    PanelState::Register(Id());
    for (int i = 0; i < 256; i++) history[i] = 0.0f;
}

void FabricLatencyGraph::Render() {
    if (!PanelState::Visible(Id())) return;

    // Update history
    history[index] = (float)Telemetry::Collect().GpuLatencyUs / 10000.0f;
    index = (index + 1) % 256;

    ImGui::Begin("Fabric Latency", &visible);
    ImGui::PlotLines("Latency (ms)", history, 256, index, nullptr, 0.0f, 10.0f, ImVec2(0, 100));
    ImGui::End();
}
