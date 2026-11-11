#include "ide/EncryptionMonitorPanel.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "ide/PanelState.hpp"
#include <imgui.h>
#include <vector>
#include <string>

struct EncryptionStatus {
    std::string src;
    std::string dst;
    bool active;
    std::string cipher;
};

static bool visible = false;
static std::vector<EncryptionStatus> encStatus = {
    {"NodeA", "NodeB", true, "AES-256-GCM"},
    {"NodeB", "NodeC", true, "AES-256-GCM"},
    {"NodeC", "NodeD", false, "NONE"}
};

const char* EncryptionMonitorPanel::Id() { return "EncryptionMonitorPanel"; }
void EncryptionMonitorPanel::Toggle() { PanelState::Toggle(Id()); }
bool EncryptionMonitorPanel::IsWired() { return SubsystemStatus::AlwaysWired(); }

void EncryptionMonitorPanel::Init() {
    PanelState::Register(Id());
}

void EncryptionMonitorPanel::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Encryption Monitor", &visible);

    for (auto& e : encStatus) {
        ImGui::Text("%s → %s", e.src.c_str(), e.dst.c_str());
        ImGui::SameLine();

        ImVec4 color = e.active ? ImVec4(0.2f,1.0f,0.2f,1.0f)
                                : ImVec4(1.0f,0.2f,0.2f,1.0f);

        ImGui::TextColored(color, "%s (%s)", e.active ? "ENCRYPTED" : "PLAINTEXT", e.cipher.c_str());
    }

    ImGui::End();
}
