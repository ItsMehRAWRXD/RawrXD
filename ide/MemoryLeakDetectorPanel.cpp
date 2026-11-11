#include "ide/MemoryLeakDetectorPanel.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "ide/PanelState.hpp"
#include <imgui.h>
#include <vector>

static bool visible = false;
static std::vector<float> samples;

const char* MemoryLeakDetectorPanel::Id() { return "MemoryLeakDetectorPanel"; }
void MemoryLeakDetectorPanel::Toggle() { PanelState::Toggle(Id()); }
bool MemoryLeakDetectorPanel::IsWired() { return SubsystemStatus::AlwaysWired(); }

void MemoryLeakDetectorPanel::Init() {
    PanelState::Register(Id());
    samples.reserve(256);
}

void MemoryLeakDetectorPanel::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Memory Leak Detector", &visible);

    // Use ImGui's allocation metrics as proxy
    size_t mem = ImGui::GetIO().MetricsActiveAllocations;
    samples.push_back((float)mem);
    if (samples.size() > 256) samples.erase(samples.begin());

    ImGui::Text("Active Allocations: %zu", mem);

    bool leak = false;
    if (samples.size() >= 32) {
        leak = samples.back() > samples.front() * 1.25f; // 25% growth
    }

    if (leak)
        ImGui::TextColored(ImVec4(1,0.2f,0.2f,1), "⚠ Leak Suspected");
    else
        ImGui::TextColored(ImVec4(0.2f,1,0.2f,1), "✓ Stable");

    if (!samples.empty()) {
        ImGui::PlotLines("Allocations", samples.data(), (int)samples.size(), 0, nullptr, 0.0f, FLT_MAX, ImVec2(0, 100));
    }

    ImGui::End();
}
