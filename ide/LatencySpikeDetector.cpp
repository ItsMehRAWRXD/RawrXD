#include "ide/LatencySpikeDetector.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "ide/PanelState.hpp"
#include "sovereign/SovereignTelemetry.hpp"
#include <imgui.h>

static bool visible = false;
static float lastLatency = 0.0f;

const char* LatencySpikeDetector::Id() { return "LatencySpikeDetector"; }
void LatencySpikeDetector::Toggle() { PanelState::Toggle(Id()); }
bool LatencySpikeDetector::IsWired() { return SubsystemStatus::AlwaysWired(); }

void LatencySpikeDetector::Init() {
    PanelState::Register(Id());
}

void LatencySpikeDetector::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Latency Spike Detector", &visible);

    auto t = Telemetry::Collect();
    float current = (float)t.GpuLatencyUs;

    float delta = current - lastLatency;
    lastLatency = current;

    if (delta > 5000.0f)
        ImGui::TextColored(ImVec4(1,0.2f,0.2f,1), "SPIKE DETECTED: +%.2f us", delta);
    else
        ImGui::TextColored(ImVec4(0.2f,1,0.2f,1), "Stable: %.2f us (%.2f us)", current, delta);

    ImGui::End();
}
