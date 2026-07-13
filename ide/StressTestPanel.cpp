#include "ide/StressTestPanel.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "ide/PanelState.hpp"
#include "tests/FabricStressTester.hpp"
#include <imgui.h>

static bool visible = false;
static int iterations = 100;
static bool running = false;

const char* StressTestPanel::Id() { return "StressTestPanel"; }
void StressTestPanel::Toggle() { PanelState::Toggle(Id()); }
bool StressTestPanel::IsWired() { return SubsystemStatus::AlwaysWired(); }

void StressTestPanel::Init() {
    PanelState::Register(Id());
    FabricStressTester::Init();
}

void StressTestPanel::RunStressTest(int iters) {
    running = true;
    FabricStressTester::RunLoop(iters);
    running = false;
}

void StressTestPanel::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Fabric Stress Test", &visible);

    ImGui::InputInt("Iterations", &iterations);
    
    if (ImGui::Button("Run Once")) {
        FabricStressTester::RunOnce();
    }
    
    ImGui::SameLine();
    
    if (ImGui::Button("Run Loop") && !running) {
        RunStressTest(iterations);
    }
    
    if (running) {
        ImGui::TextColored(ImVec4(1,1,0,1), "Running...");
    }

    ImGui::End();
}
