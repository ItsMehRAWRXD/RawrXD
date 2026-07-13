#include "ide/NodeLoadBars.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "ide/PanelState.hpp"
#include <imgui.h>
#include <vector>
#include <string>

struct NodeLoad {
    std::string name;
    float loadPercent;
};

static bool visible = false;
static std::vector<NodeLoad> nodeLoads = {
    {"NodeA", 45.0f},
    {"NodeB", 72.0f},
    {"NodeC", 23.0f},
    {"NodeD", 89.0f}
};

const char* NodeLoadBars::Id() { return "NodeLoadBars"; }
void NodeLoadBars::Toggle() { PanelState::Toggle(Id()); }
bool NodeLoadBars::IsWired() { return SubsystemStatus::AlwaysWired(); }

void NodeLoadBars::Init() {
    PanelState::Register(Id());
}

void NodeLoadBars::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Node Load Distribution", &visible);

    for (auto& n : nodeLoads) {
        ImGui::Text("%s", n.name.c_str());
        ImGui::ProgressBar(n.loadPercent / 100.0f, ImVec2(200, 20));
    }

    ImGui::End();
}
