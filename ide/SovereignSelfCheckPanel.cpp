#include "ide/SovereignSelfCheckPanel.hpp"
#include "sovereign/SovereignSelfCheck.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include "ide/PanelState.hpp"
#include <imgui.h>

static bool visible = false;

const char* SovereignSelfCheckPanel::Id() {
    return "SovereignSelfCheckPanel";
}

void SovereignSelfCheckPanel::Init() {
    PanelState::Register(Id());
}

void SovereignSelfCheckPanel::Toggle() {
    PanelState::Toggle(Id());
}

bool SovereignSelfCheckPanel::IsWired() {
    return SubsystemStatus::AlwaysWired();
}

static void DrawResult(const SovereignSelfCheck::CheckResult& r) {
    if (r.ok)
        ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.2f, 1.0f), "[OK] %s - %s",
                           r.name.c_str(), r.detail.c_str());
    else
        ImGui::TextColored(ImVec4(1.0f, 0.2f, 0.2f, 1.0f), "[FAIL] %s - %s",
                           r.name.c_str(), r.detail.c_str());
}

void SovereignSelfCheckPanel::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Sovereign Self Check", &visible);

    auto results = SovereignSelfCheck::RunAll();
    for (auto& r : results)
        DrawResult(r);

    ImGui::End();
}
