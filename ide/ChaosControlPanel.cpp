#include "ide/ChaosControlPanel.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "ide/PanelState.hpp"
#include "tests/LoadSimulator.hpp"
#include "tests/NodeFailureEmulator.hpp"
#include "tests/ConsensusChaosMonkey.hpp"
#include <imgui.h>

static bool visible = false;
static float targetLoad = 0.7f;

const char* ChaosControlPanel::Id() { return "ChaosControlPanel"; }
void ChaosControlPanel::Toggle() { PanelState::Toggle(Id()); }
bool ChaosControlPanel::IsWired() { return SubsystemStatus::AlwaysWired(); }

void ChaosControlPanel::Init() {
    PanelState::Register(Id());
    LoadSimulator::Init();
    NodeFailureEmulator::Init();
    ConsensusChaosMonkey::Init();
}

void ChaosControlPanel::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Chaos Engineering Control", &visible);

    // Load Simulation
    ImGui::Separator();
    ImGui::Text("Load Simulator");
    ImGui::SliderFloat("Target Load", &targetLoad, 0.0f, 1.0f);
    
    if (ImGui::Button("Start Load Sim")) {
        LoadSimulator::StartSimulation(targetLoad);
    }
    ImGui::SameLine();
    if (ImGui::Button("Stop Load Sim")) {
        LoadSimulator::StopSimulation();
    }
    
    if (LoadSimulator::IsRunning()) {
        ImGui::TextColored(ImVec4(1,1,0,1), "Current: %.2f%%", LoadSimulator::GetCurrentLoad() * 100);
    }

    // Node Failure
    ImGui::Separator();
    ImGui::Text("Node Failure Emulator");
    if (ImGui::Button("Fail Random Node")) {
        NodeFailureEmulator::FailRandomNode();
    }
    ImGui::SameLine();
    if (ImGui::Button("Recover All")) {
        NodeFailureEmulator::RecoverAllNodes();
    }

    // Consensus Chaos
    ImGui::Separator();
    ImGui::Text("Consensus Chaos Monkey");
    if (ImGui::Button("Inject Latency")) {
        ConsensusChaosMonkey::InjectLatencySpike(100);
    }
    ImGui::SameLine();
    if (ImGui::Button("Drop Vote")) {
        ConsensusChaosMonkey::DropRandomVote();
    }
    ImGui::SameLine();
    if (ImGui::Button("Corrupt Msg")) {
        ConsensusChaosMonkey::CorruptRandomMessage();
    }

    ImGui::End();
}
