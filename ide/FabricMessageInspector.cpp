#include "ide/FabricMessageInspector.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "ide/PanelState.hpp"
#include <imgui.h>
#include <vector>
#include <string>

struct Message {
    std::string type;
    std::string payload;
    uint64_t timestamp;
};

static bool visible = false;
static std::vector<Message> messages = {
    {"kv_state", "{\"hot\":1024,\"warm\":512}", 0},
    {"expert_load", "{\"expert_id\":5,\"load\":0.75}", 0},
    {"consensus_vote", "{\"proposal\":123,\"vote\":true}", 0}
};

const char* FabricMessageInspector::Id() { return "FabricMessageInspector"; }
void FabricMessageInspector::Toggle() { PanelState::Toggle(Id()); }
bool FabricMessageInspector::IsWired() { return SubsystemStatus::AlwaysWired(); }

void FabricMessageInspector::Init() {
    PanelState::Register(Id());
}

void FabricMessageInspector::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Fabric Message Inspector", &visible);

    for (auto& m : messages) {
        ImGui::TextColored(ImVec4(1,1,0.2f,1), "%s", m.type.c_str());
        ImGui::TextWrapped("%s", m.payload.c_str());
        ImGui::Separator();
    }

    ImGui::End();
}
