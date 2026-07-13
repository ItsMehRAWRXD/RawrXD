#include "ide/PacketTraceVisualizer.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "ide/PanelState.hpp"
#include <imgui.h>
#include <vector>
#include <string>

struct Hop {
    std::string node;
    uint64_t latency;
};

static bool visible = false;
static std::vector<Hop> trace = {
    {"NodeA", 100},
    {"NodeB", 250},
    {"NodeC", 180},
    {"NodeD", 320}
};

const char* PacketTraceVisualizer::Id() { return "PacketTraceVisualizer"; }
void PacketTraceVisualizer::Toggle() { PanelState::Toggle(Id()); }
bool PacketTraceVisualizer::IsWired() { return SubsystemStatus::AlwaysWired(); }

void PacketTraceVisualizer::Init() {
    PanelState::Register(Id());
}

void PacketTraceVisualizer::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Packet Trace", &visible);

    ImDrawList* draw = ImGui::GetWindowDrawList();
    ImVec2 pos = ImGui::GetCursorScreenPos();
    
    float x = pos.x + 20;
    float y = pos.y + 30;

    for (size_t i = 0; i < trace.size(); i++) {
        // Draw node
        draw->AddCircleFilled(ImVec2(x, y), 15.0f, IM_COL32(100, 200, 100, 255));
        draw->AddText(ImVec2(x - 25, y + 20), IM_COL32(255, 255, 255, 255), trace[i].node.c_str());
        
        // Draw latency
        if (i < trace.size() - 1) {
            draw->AddLine(ImVec2(x + 15, y), ImVec2(x + 80, y), IM_COL32(150, 150, 150, 255), 2.0f);
            draw->AddText(ImVec2(x + 30, y - 15), IM_COL32(200, 200, 200, 255), 
                         (std::to_string(trace[i+1].latency) + "us").c_str());
            x += 100;
        }
    }

    ImGui::Dummy(ImVec2(0, 80));
    ImGui::End();
}
