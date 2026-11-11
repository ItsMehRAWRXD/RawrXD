#include "ide/NodeRing.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "sovereign/Fabric.hpp"
#include "ide/PanelState.hpp"
#include <imgui.h>
#include <cmath>

static std::vector<std::string> nodes;
static bool visible = false;

const char* NodeRing::Id() { return "NodeRing"; }
void NodeRing::Toggle() { PanelState::Toggle(Id()); }
bool NodeRing::IsWired() { return SubsystemStatus::AlwaysWired(); }

void NodeRing::Init() {
    PanelState::Register(Id());
    // nodes = Fabric::ListNodes(); // Would call actual API
    nodes = {"NodeA", "NodeB", "NodeC", "NodeD"}; // Placeholder
}

void NodeRing::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Node Ring", &visible);

    ImVec2 center = ImGui::GetCursorScreenPos();
    center.x += 150;
    center.y += 150;
    float radius = 100.0f;

    ImDrawList* draw = ImGui::GetWindowDrawList();

    int count = nodes.size();
    for (int i = 0; i < count; i++) {
        float angle = (2.0f * 3.14159f * i) / count;
        float x = center.x + radius * cosf(angle);
        float y = center.y + radius * sinf(angle);

        draw->AddCircleFilled(ImVec2(x, y), 15.0f, IM_COL32(100, 200, 100, 255));
        draw->AddText(ImVec2(x - 20, y + 20), IM_COL32(255, 255, 255, 255), nodes[i].c_str());
    }

    draw->AddCircle(center, radius, IM_COL32(150, 150, 150, 255), 32, 2.0f);

    ImGui::End();
}
