#include "ide/KeyExchangeVisualizer.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "ide/PanelState.hpp"
#include <imgui.h>
#include <vector>
#include <string>

struct KeyExchange {
    std::string nodeA;
    std::string nodeB;
    std::string method;
    std::string status;
};

static bool visible = false;
static std::vector<KeyExchange> exchanges = {
    {"NodeA", "NodeB", "ECDH-P256", "COMPLETE"},
    {"NodeB", "NodeC", "ECDH-P256", "IN_PROGRESS"},
    {"NodeC", "NodeD", "ECDH-P256", "PENDING"}
};

const char* KeyExchangeVisualizer::Id() { return "KeyExchangeVisualizer"; }
void KeyExchangeVisualizer::Toggle() { PanelState::Toggle(Id()); }
bool KeyExchangeVisualizer::IsWired() { return SubsystemStatus::AlwaysWired(); }

void KeyExchangeVisualizer::Init() {
    PanelState::Register(Id());
}

void KeyExchangeVisualizer::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Key Exchange Visualizer", &visible);

    for (auto& k : exchanges) {
        ImGui::Text("%s ↔ %s", k.nodeA.c_str(), k.nodeB.c_str());
        
        ImVec4 color;
        if (k.status == "COMPLETE") color = ImVec4(0.2f, 1.0f, 0.2f, 1.0f);
        else if (k.status == "IN_PROGRESS") color = ImVec4(1.0f, 1.0f, 0.2f, 1.0f);
        else color = ImVec4(1.0f, 0.5f, 0.2f, 1.0f);
        
        ImGui::Text("Method: %s", k.method.c_str());
        ImGui::TextColored(color, "Status: %s", k.status.c_str());
        ImGui::Separator();
    }

    ImGui::End();
}
