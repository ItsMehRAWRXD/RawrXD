#include "ide/FabricLinkHeatmap.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "ide/PanelState.hpp"
#include <imgui.h>
#include <vector>

struct LinkInfo {
    std::string src;
    std::string dst;
    uint64_t latencyUs;
};

static bool visible = false;
static std::vector<LinkInfo> links = {
    {"NodeA", "NodeB", 2500},
    {"NodeB", "NodeC", 3200},
    {"NodeC", "NodeD", 1800},
    {"NodeD", "NodeA", 4100}
};

const char* FabricLinkHeatmap::Id() { return "FabricLinkHeatmap"; }
void FabricLinkHeatmap::Toggle() { PanelState::Toggle(Id()); }
bool FabricLinkHeatmap::IsWired() { return SubsystemStatus::AlwaysWired(); }

void FabricLinkHeatmap::Init() {
    PanelState::Register(Id());
}

void FabricLinkHeatmap::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Fabric Link Latency Heatmap", &visible);

    for (auto& link : links) {
        float intensity = (float)link.latencyUs / 5000.0f;
        if (intensity > 1.0f) intensity = 1.0f;

        ImVec4 color(intensity, 1.0f - intensity, 0.2f, 1.0f);
        ImGui::TextColored(color, "%s → %s : %llu us",
                           link.src.c_str(), link.dst.c_str(), link.latencyUs);
    }

    ImGui::End();
}
