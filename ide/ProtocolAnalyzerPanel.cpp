#include "ide/ProtocolAnalyzerPanel.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "ide/PanelState.hpp"
#include <imgui.h>
#include <vector>
#include <string>

struct PacketInfo {
    std::string src;
    std::string dst;
    std::string type;
    uint64_t timestamp;
};

static bool visible = false;
static std::vector<PacketInfo> packets = {
    {"NodeA", "NodeB", "kv_state", 0},
    {"NodeB", "NodeC", "expert_load", 0},
    {"NodeC", "NodeD", "consensus_vote", 0}
};

const char* ProtocolAnalyzerPanel::Id() { return "ProtocolAnalyzerPanel"; }
void ProtocolAnalyzerPanel::Toggle() { PanelState::Toggle(Id()); }
bool ProtocolAnalyzerPanel::IsWired() { return SubsystemStatus::AlwaysWired(); }

void ProtocolAnalyzerPanel::Init() {
    PanelState::Register(Id());
}

void ProtocolAnalyzerPanel::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Protocol Analyzer", &visible);

    ImGui::Text("Recent Packets (%zu)", packets.size());
    ImGui::Separator();

    for (auto& p : packets) {
        ImGui::Text("%s → %s", p.src.c_str(), p.dst.c_str());
        ImGui::SameLine();
        ImVec4 color = ImVec4(0.6f,0.6f,1.0f,1.0f);
        ImGui::TextColored(color, "[%s]", p.type.c_str());
    }

    ImGui::End();
}
