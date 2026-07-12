#include "ide/SecureChannelIntegrityPanel.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "ide/PanelState.hpp"
#include <imgui.h>
#include <vector>
#include <string>

struct SecureChannel {
    std::string src;
    std::string dst;
    bool integrityOk;
    uint64_t lastVerified;
};

static bool visible = false;
static std::vector<SecureChannel> channels = {
    {"NodeA", "NodeB", true, 0},
    {"NodeB", "NodeC", true, 0},
    {"NodeC", "NodeD", false, 0}
};

const char* SecureChannelIntegrityPanel::Id() { return "SecureChannelIntegrityPanel"; }
void SecureChannelIntegrityPanel::Toggle() { PanelState::Toggle(Id()); }
bool SecureChannelIntegrityPanel::IsWired() { return SubsystemStatus::AlwaysWired(); }

void SecureChannelIntegrityPanel::Init() {
    PanelState::Register(Id());
}

void SecureChannelIntegrityPanel::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Secure Channel Integrity", &visible);

    for (auto& c : channels) {
        ImGui::Text("%s → %s", c.src.c_str(), c.dst.c_str());

        ImVec4 color = c.integrityOk ? ImVec4(0.2f,1.0f,0.2f,1.0f)
                                     : ImVec4(1.0f,0.2f,0.2f,1.0f);

        ImGui::TextColored(color, "Integrity: %s",
                           c.integrityOk ? "✓ OK" : "✗ FAILED");

        ImGui::Separator();
    }

    ImGui::End();
}
