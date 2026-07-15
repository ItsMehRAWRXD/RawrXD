#include "EternalVoidPanel.hpp"
#include "../eternal/EternalVoidEngine.hpp"
#include "../eternal/EternalVoidLoop.hpp"
#include <imgui.h>
#include <algorithm>

namespace IDE {

EternalVoidPanel::EternalVoidPanel()
    : m_initialized(false)
    , m_visible(false)
    , m_currentTab(0)
{
    ClearInputBuffers();
    memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
}

EternalVoidPanel::~EternalVoidPanel() {
    if (m_initialized) {
        Shutdown();
    }
}

bool EternalVoidPanel::Initialize() {
    if (m_initialized) return true;
    m_initialized = true;
    return true;
}

void EternalVoidPanel::Shutdown() {
    if (!m_initialized) return;
    m_initialized = false;
}

bool EternalVoidPanel::IsInitialized() const {
    return m_initialized;
}

void EternalVoidPanel::Show() {
    m_visible = true;
}

void EternalVoidPanel::Hide() {
    m_visible = false;
}

void EternalVoidPanel::ToggleVisibility() {
    m_visible = !m_visible;
}

bool EternalVoidPanel::IsVisible() const {
    return m_visible;
}

void EternalVoidPanel::Render() {
    if (!m_visible || !m_initialized) return;
    RenderWindow();
}

void EternalVoidPanel::RenderWindow() {
    ImGui::SetNextWindowSize(ImVec2(900, 700), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Eternal Void (Layer 113)", &m_visible)) {
        RenderTabBar();
        
        switch (static_cast<Tab>(m_currentTab)) {
            case Tab::EternalStructures:
                RenderEternalStructuresTab();
                break;
            case Tab::EmptinessAbsolutes:
                RenderEmptinessAbsolutesTab();
                break;
            case Tab::NothingnessAbsolutes:
                RenderNothingnessAbsolutesTab();
                break;
            case Tab::SilenceAbsolutes:
                RenderSilenceAbsolutesTab();
                break;
            case Tab::StillnessAbsolutes:
                RenderStillnessAbsolutesTab();
                break;
            case Tab::DarknessAbsolutes:
                RenderDarknessAbsolutesTab();
                break;
            case Tab::Metrics:
                RenderMetricsTab();
                break;
            case Tab::Settings:
                RenderSettingsTab();
                break;
            default:
                break;
        }
    }
    ImGui::End();
}

void EternalVoidPanel::RenderTabBar() {
    if (ImGui::BeginTabBar("EternalVoidTabs")) {
        if (ImGui::BeginTabItem("Eternal Structures")) {
            m_currentTab = static_cast<int>(Tab::EternalStructures);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Emptiness Absolutes")) {
            m_currentTab = static_cast<int>(Tab::EmptinessAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Nothingness Absolutes")) {
            m_currentTab = static_cast<int>(Tab::NothingnessAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Silence Absolutes")) {
            m_currentTab = static_cast<int>(Tab::SilenceAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Stillness Absolutes")) {
            m_currentTab = static_cast<int>(Tab::StillnessAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Darkness Absolutes")) {
            m_currentTab = static_cast<int>(Tab::DarknessAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Metrics")) {
            m_currentTab = static_cast<int>(Tab::Metrics);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Settings")) {
            m_currentTab = static_cast<int>(Tab::Settings);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

void EternalVoidPanel::RenderEternalStructuresTab() {
    ImGui::Text("Eternal Void Structures");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewEternalStructure();
    }
    
    ImGui::Spacing();
    
    auto structures = EternalVoid::EternalVoidEngine::GetAllEternalVoidStructures();
    
    if (ImGui::BeginTable("EternalStructuresTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Eternal Void");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& structure : structures) {
            if (!FilterMatches(structure.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(structure.name.c_str(), m_selectedEternalId == structure.eternalId, 
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectEternalStructure(structure.eternalId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(structure.eternalVoid);
            
            ImGui::TableSetColumnIndex(2);
            if (structure.isEternalVoid) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "ETERNAL VOID");
            } else if (structure.isActive) {
                ImGui::Text("Active");
            } else {
                ImGui::TextDisabled("Inactive");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(structure.eternalId.c_str());
            if (ImGui::SmallButton("Deepen")) {
                OnDeepenEternalVoid(structure.eternalId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                EternalVoid::EternalVoidEngine::DestroyEternalVoidStructure(structure.eternalId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedEternalId.empty()) {
        RenderEternalStructureDetails(m_selectedEternalId);
    }
}

void EternalVoidPanel::RenderEmptinessAbsolutesTab() {
    ImGui::Text("Emptiness Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewEmptinessAbsolute();
    }
    
    ImGui::Spacing();
    
    auto emptinesses = EternalVoid::EternalVoidEngine::GetAllEmptinessAbsolutes();
    
    if (ImGui::BeginTable("EmptinessAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Emptiness");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& emptiness : emptinesses) {
            if (!FilterMatches(emptiness.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(emptiness.name.c_str(), m_selectedEmptinessId == emptiness.emptinessId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectEmptinessAbsolute(emptiness.emptinessId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(emptiness.emptiness);
            
            ImGui::TableSetColumnIndex(2);
            if (emptiness.isEmpty) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "EMPTY");
            } else {
                ImGui::Text("Forming");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(emptiness.emptinessId.c_str());
            if (ImGui::SmallButton("Create Vacancy")) {
                OnCreateVacancy(emptiness.emptinessId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                EternalVoid::EternalVoidEngine::DestroyEmptinessAbsolute(emptiness.emptinessId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedEmptinessId.empty()) {
        RenderEmptinessAbsoluteDetails(m_selectedEmptinessId);
    }
}

void EternalVoidPanel::RenderNothingnessAbsolutesTab() {
    ImGui::Text("Nothingness Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewNothingnessAbsolute();
    }
    
    ImGui::Spacing();
    
    auto nothingnesses = EternalVoid::EternalVoidEngine::GetAllNothingnessAbsolutes();
    
    if (ImGui::BeginTable("NothingnessAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Nothingness");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& nothingness : nothingnesses) {
            if (!FilterMatches(nothingness.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(nothingness.name.c_str(), m_selectedNothingnessId == nothingness.nothingnessId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectNothingnessAbsolute(nothingness.nothingnessId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(nothingness.nothingness);
            
            ImGui::TableSetColumnIndex(2);
            if (nothingness.isNothing) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "NOTHING");
            } else {
                ImGui::Text("Forming");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(nothingness.nothingnessId.c_str());
            if (ImGui::SmallButton("Embrace Nullity")) {
                OnEmbraceNullity(nothingness.nothingnessId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                EternalVoid::EternalVoidEngine::DestroyNothingnessAbsolute(nothingness.nothingnessId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedNothingnessId.empty()) {
        RenderNothingnessAbsoluteDetails(m_selectedNothingnessId);
    }
}

void EternalVoidPanel::RenderSilenceAbsolutesTab() {
    ImGui::Text("Silence Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewSilenceAbsolute();
    }
    
    ImGui::Spacing();
    
    auto silences = EternalVoid::EternalVoidEngine::GetAllSilenceAbsolutes();
    
    if (ImGui::BeginTable("SilenceAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Silence");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& silence : silences) {
            if (!FilterMatches(silence.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(silence.name.c_str(), m_selectedSilenceId == silence.silenceId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectSilenceAbsolute(silence.silenceId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(silence.silence);
            
            ImGui::TableSetColumnIndex(2);
            if (silence.isSilent) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "SILENT");
            } else {
                ImGui::Text("Forming");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(silence.silenceId.c_str());
            if (ImGui::SmallButton("Cultivate Quietude")) {
                OnCultivateQuietude(silence.silenceId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                EternalVoid::EternalVoidEngine::DestroySilenceAbsolute(silence.silenceId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedSilenceId.empty()) {
        RenderSilenceAbsoluteDetails(m_selectedSilenceId);
    }
}

void EternalVoidPanel::RenderStillnessAbsolutesTab() {
    ImGui::Text("Stillness Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewStillnessAbsolute();
    }
    
    ImGui::Spacing();
    
    auto stillnesses = EternalVoid::EternalVoidEngine::GetAllStillnessAbsolutes();
    
    if (ImGui::BeginTable("StillnessAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Stillness");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& stillness : stillnesses) {
            if (!FilterMatches(stillness.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(stillness.name.c_str(), m_selectedStillnessId == stillness.stillnessId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectStillnessAbsolute(stillness.stillnessId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(stillness.stillness);
            
            ImGui::TableSetColumnIndex(2);
            if (stillness.isStill) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "STILL");
            } else {
                ImGui::Text("Forming");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(stillness.stillnessId.c_str());
            if (ImGui::SmallButton("Achieve Motionlessness")) {
                OnAchieveMotionlessness(stillness.stillnessId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                EternalVoid::EternalVoidEngine::DestroyStillnessAbsolute(stillness.stillnessId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedStillnessId.empty()) {
        RenderStillnessAbsoluteDetails(m_selectedStillnessId);
    }
}

void EternalVoidPanel::RenderDarknessAbsolutesTab() {
    ImGui::Text("Darkness Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewDarknessAbsolute();
    }
    
    ImGui::Spacing();
    
    auto darknesses = EternalVoid::EternalVoidEngine::GetAllDarknessAbsolutes();
    
    if (ImGui::BeginTable("DarknessAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Darkness");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& darkness : darknesses) {
            if (!FilterMatches(darkness.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(darkness.name.c_str(), m_selectedDarknessId == darkness.darknessId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectDarknessAbsolute(darkness.darknessId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(darkness.darkness);
            
            ImGui::TableSetColumnIndex(2);
            if (darkness.isDark) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "DARK");
            } else {
                ImGui::Text("Forming");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(darkness.darknessId.c_str());
            if (ImGui::SmallButton("Deepen Obscurity")) {
                OnDeepenObscurity(darkness.darknessId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                EternalVoid::EternalVoidEngine::DestroyDarknessAbsolute(darkness.darknessId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedDarknessId.empty()) {
        RenderDarknessAbsoluteDetails(m_selectedDarknessId);
    }
}

void EternalVoidPanel::RenderMetricsTab() {
    ImGui::Text("Eternal Void Metrics");
    ImGui::Separator();
    
    auto metrics = EternalVoid::EternalVoidEngine::GetEternalVoidMetrics();
    auto loopMetrics = EternalVoid::EternalVoidLoop::GetMetrics();
    
    ImGui::Columns(2, "MetricsColumns");
    
    ImGui::Text("Structures:");
    ImGui::Text("  Eternal Structures: %d", metrics.value("eternalStructureCount", 0));
    ImGui::Text("  Emptiness Absolutes: %d", metrics.value("emptinessAbsoluteCount", 0));
    ImGui::Text("  Nothingness Absolutes: %d", metrics.value("nothingnessAbsoluteCount", 0));
    ImGui::Text("  Silence Absolutes: %d", metrics.value("silenceAbsoluteCount", 0));
    ImGui::Text("  Stillness Absolutes: %d", metrics.value("stillnessAbsoluteCount", 0));
    ImGui::Text("  Darkness Absolutes: %d", metrics.value("darknessAbsoluteCount", 0));
    
    ImGui::NextColumn();
    
    ImGui::Text("Performance:");
    ImGui::Text("  Current TPS: %.1f", loopMetrics.currentTPS);
    ImGui::Text("  Current FPS: %.1f", loopMetrics.currentFPS);
    ImGui::Text("  Total Ticks: %lld", loopMetrics.totalTicks);
    ImGui::Text("  Total Frames: %lld", loopMetrics.totalFrames);
    ImGui::Text("  Avg Tick Time: %.2f ms", loopMetrics.averageTickTimeMs);
    ImGui::Text("  Avg Frame Time: %.2f ms", loopMetrics.averageFrameTimeMs);
    
    ImGui::Columns(1);
    
    ImGui::Separator();
    ImGui::Text("Eternal Void Values:");
    
    float totalEternalVoid = metrics.value("totalEternalVoid", 0.0f);
    float totalEmptiness = metrics.value("totalEmptiness", 0.0f);
    float totalNothingness = metrics.value("totalNothingness", 0.0f);
    float totalSilence = metrics.value("totalSilence", 0.0f);
    float totalStillness = metrics.value("totalStillness", 0.0f);
    float totalDarkness = metrics.value("totalDarkness", 0.0f);
    
    ImGui::Text("Total Eternal Void: %.2f", totalEternalVoid);
    ImGui::Text("Total Emptiness: %.2f", totalEmptiness);
    ImGui::Text("Total Nothingness: %.2f", totalNothingness);
    ImGui::Text("Total Silence: %.2f", totalSilence);
    ImGui::Text("Total Stillness: %.2f", totalStillness);
    ImGui::Text("Total Darkness: %.2f", totalDarkness);
}

void EternalVoidPanel::RenderSettingsTab() {
    ImGui::Text("Eternal Void Settings");
    ImGui::Separator();
    
    auto config = EternalVoid::EternalVoidLoop::GetConfig();
    
    ImGui::SliderInt("Target TPS", &config.targetTPS, 1, 120);
    ImGui::SliderInt("Max FPS", &config.maxFPS, 1, 240);
    ImGui::Checkbox("Enable Frame Limiting", &config.enableFrameLimiting);
    ImGui::Checkbox("Enable Metrics", &config.enableMetrics);
    
    if (ImGui::Button("Apply Settings")) {
        EternalVoid::EternalVoidLoop::SetConfig(config);
    }
}

void EternalVoidPanel::RenderEternalStructureDetails(const std::string& eternalId) {
    auto structure = EternalVoid::EternalVoidEngine::GetEternalVoidStructure(eternalId);
    if (!structure) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", structure->name.c_str());
    
    ImGui::Text("Eternal Void: %.2f", structure->eternalVoid);
    ImGui::ProgressBar(structure->eternalVoid);
    
    ImGui::Text("Emptiness: %.2f", structure->emptiness);
    ImGui::ProgressBar(structure->emptiness);
    
    ImGui::Text("Nothingness: %.2f", structure->nothingness);
    ImGui::ProgressBar(structure->nothingness);
    
    ImGui::Text("Silence: %.2f", structure->silence);
    ImGui::ProgressBar(structure->silence);
    
    ImGui::Text("Stillness: %.2f", structure->stillness);
    ImGui::ProgressBar(structure->stillness);
    
    ImGui::Text("Darkness: %.2f", structure->darkness);
    ImGui::ProgressBar(structure->darkness);
    
    if (ImGui::Button("Deepen Eternal Void")) OnDeepenEternalVoid(eternalId);
    ImGui::SameLine();
    if (ImGui::Button("Embrace Emptiness")) OnEmbraceEmptiness(eternalId);
    ImGui::SameLine();
    if (ImGui::Button("Accept Nothingness")) OnAcceptNothingness(eternalId);
    ImGui::SameLine();
    if (ImGui::Button("Enter Silence")) OnEnterSilence(eternalId);
    ImGui::SameLine();
    if (ImGui::Button("Achieve Stillness")) OnAchieveStillness(eternalId);
    ImGui::SameLine();
    if (ImGui::Button("Descend Into Darkness")) OnDescendIntoDarkness(eternalId);
}

void EternalVoidPanel::RenderEmptinessAbsoluteDetails(const std::string& emptinessId) {
    auto emptiness = EternalVoid::EternalVoidEngine::GetEmptinessAbsolute(emptinessId);
    if (!emptiness) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", emptiness->name.c_str());
    
    ImGui::Text("Emptiness: %.2f", emptiness->emptiness);
    ImGui::ProgressBar(emptiness->emptiness);
    
    ImGui::Text("Vacancy: %.2f", emptiness->vacancy);
    ImGui::ProgressBar(emptiness->vacancy);
    
    ImGui::Text("Hollowness: %.2f", emptiness->hollowness);
    ImGui::ProgressBar(emptiness->hollowness);
    
    if (ImGui::Button("Create Vacancy")) OnCreateVacancy(emptinessId);
    ImGui::SameLine();
    if (ImGui::Button("Deepen Hollowness")) OnDeepenHollowness(emptinessId);
    ImGui::SameLine();
    if (ImGui::Button("Declare Empty")) OnDeclareEmpty(emptinessId);
}

void EternalVoidPanel::RenderNothingnessAbsoluteDetails(const std::string& nothingnessId) {
    auto nothingness = EternalVoid::EternalVoidEngine::GetNothingnessAbsolute(nothingnessId);
    if (!nothingness) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", nothingness->name.c_str());
    
    ImGui::Text("Nothingness: %.2f", nothingness->nothingness);
    ImGui::ProgressBar(nothingness->nothingness);
    
    ImGui::Text("Nullity: %.2f", nothingness->nullity);
    ImGui::ProgressBar(nothingness->nullity);
    
    ImGui::Text("Voidness: %.2f", nothingness->voidness);
    ImGui::ProgressBar(nothingness->voidness);
    
    if (ImGui::Button("Embrace Nullity")) OnEmbraceNullity(nothingnessId);
    ImGui::SameLine();
    if (ImGui::Button("Expand Voidness")) OnExpandVoidness(nothingnessId);
    ImGui::SameLine();
    if (ImGui::Button("Declare Nothing")) OnDeclareNothing(nothingnessId);
}

void EternalVoidPanel::RenderSilenceAbsoluteDetails(const std::string& silenceId) {
    auto silence = EternalVoid::EternalVoidEngine::GetSilenceAbsolute(silenceId);
    if (!silence) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", silence->name.c_str());
    
    ImGui::Text("Silence: %.2f", silence->silence);
    ImGui::ProgressBar(silence->silence);
    
    ImGui::Text("Quietude: %.2f", silence->quietude);
    ImGui::ProgressBar(silence->quietude);
    
    ImGui::Text("Muteness: %.2f", silence->muteness);
    ImGui::ProgressBar(silence->muteness);
    
    if (ImGui::Button("Cultivate Quietude")) OnCultivateQuietude(silenceId);
    ImGui::SameLine();
    if (ImGui::Button("Deepen Muteness")) OnDeepenMuteness(silenceId);
    ImGui::SameLine();
    if (ImGui::Button("Declare Silent")) OnDeclareSilent(silenceId);
}

void EternalVoidPanel::RenderStillnessAbsoluteDetails(const std::string& stillnessId) {
    auto stillness = EternalVoid::EternalVoidEngine::GetStillnessAbsolute(stillnessId);
    if (!stillness) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", stillness->name.c_str());
    
    ImGui::Text("Stillness: %.2f", stillness->stillness);
    ImGui::ProgressBar(stillness->stillness);
    
    ImGui::Text("Motionlessness: %.2f", stillness->motionlessness);
    ImGui::ProgressBar(stillness->motionlessness);
    
    ImGui::Text("Calmness: %.2f", stillness->calmness);
    ImGui::ProgressBar(stillness->calmness);
    
    if (ImGui::Button("Achieve Motionlessness")) OnAchieveMotionlessness(stillnessId);
    ImGui::SameLine();
    if (ImGui::Button("Cultivate Calmness")) OnCultivateCalmness(stillnessId);
    ImGui::SameLine();
    if (ImGui::Button("Declare Still")) OnDeclareStill(stillnessId);
}

void EternalVoidPanel::RenderDarknessAbsoluteDetails(const std::string& darknessId) {
    auto darkness = EternalVoid::EternalVoidEngine::GetDarknessAbsolute(darknessId);
    if (!darkness) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", darkness->name.c_str());
    
    ImGui::Text("Darkness: %.2f", darkness->darkness);
    ImGui::ProgressBar(darkness->darkness);
    
    ImGui::Text("Obscurity: %.2f", darkness->obscurity);
    ImGui::ProgressBar(darkness->obscurity);
    
    ImGui::Text("Shadow: %.2f", darkness->shadow);
    ImGui::ProgressBar(darkness->shadow);
    
    if (ImGui::Button("Deepen Obscurity")) OnDeepenObscurity(darknessId);
    ImGui::SameLine();
    if (ImGui::Button("Extend Shadow")) OnExtendShadow(darknessId);
    ImGui::SameLine();
    if (ImGui::Button("Declare Dark")) OnDeclareDark(darknessId);
}

void EternalVoidPanel::SelectEternalStructure(const std::string& eternalId) {
    m_selectedEternalId = eternalId;
}

void EternalVoidPanel::SelectEmptinessAbsolute(const std::string& emptinessId) {
    m_selectedEmptinessId = emptinessId;
}

void EternalVoidPanel::SelectNothingnessAbsolute(const std::string& nothingnessId) {
    m_selectedNothingnessId = nothingnessId;
}

void EternalVoidPanel::SelectSilenceAbsolute(const std::string& silenceId) {
    m_selectedSilenceId = silenceId;
}

void EternalVoidPanel::SelectStillnessAbsolute(const std::string& stillnessId) {
    m_selectedStillnessId = stillnessId;
}

void EternalVoidPanel::SelectDarknessAbsolute(const std::string& darknessId) {
    m_selectedDarknessId = darknessId;
}

void EternalVoidPanel::CreateNewEternalStructure() {
    ImGui::OpenPopup("Create Eternal Structure");
}

void EternalVoidPanel::CreateNewEmptinessAbsolute() {
    EternalVoid::EternalVoidEngine::CreateEmptinessAbsolute("New Emptiness Absolute");
}

void EternalVoidPanel::CreateNewNothingnessAbsolute() {
    EternalVoid::EternalVoidEngine::CreateNothingnessAbsolute("New Nothingness Absolute");
}

void EternalVoidPanel::CreateNewSilenceAbsolute() {
    EternalVoid::EternalVoidEngine::CreateSilenceAbsolute("New Silence Absolute");
}

void EternalVoidPanel::CreateNewStillnessAbsolute() {
    EternalVoid::EternalVoidEngine::CreateStillnessAbsolute("New Stillness Absolute");
}

void EternalVoidPanel::CreateNewDarknessAbsolute() {
    EternalVoid::EternalVoidEngine::CreateDarknessAbsolute("New Darkness Absolute");
}

void EternalVoidPanel::ClearInputBuffers() {
    memset(m_newEternalName, 0, sizeof(m_newEternalName));
    memset(m_newEmptinessName, 0, sizeof(m_newEmptinessName));
    memset(m_newNothingnessName, 0, sizeof(m_newNothingnessName));
    memset(m_newSilenceName, 0, sizeof(m_newSilenceName));
    memset(m_newStillnessName, 0, sizeof(m_newStillnessName));
    memset(m_newDarknessName, 0, sizeof(m_newDarknessName));
}

bool EternalVoidPanel::FilterMatches(const std::string& text) const {
    if (strlen(m_filterBuffer) == 0) return true;
    return text.find(m_filterBuffer) != std::string::npos;
}

// Action handlers
void EternalVoidPanel::OnDeepenEternalVoid(const std::string& eternalId) {
    EternalVoid::EternalVoidEngine::DeepenEternalVoid(eternalId, 0.1f);
}

void EternalVoidPanel::OnEmbraceEmptiness(const std::string& eternalId) {
    EternalVoid::EternalVoidEngine::EmbraceEmptiness(eternalId, 0.1f);
}

void EternalVoidPanel::OnAcceptNothingness(const std::string& eternalId) {
    EternalVoid::EternalVoidEngine::AcceptNothingness(eternalId, 0.1f);
}

void EternalVoidPanel::OnEnterSilence(const std::string& eternalId) {
    EternalVoid::EternalVoidEngine::EnterSilence(eternalId, 0.1f);
}

void EternalVoidPanel::OnAchieveStillness(const std::string& eternalId) {
    EternalVoid::EternalVoidEngine::AchieveStillness(eternalId, 0.1f);
}

void EternalVoidPanel::OnDescendIntoDarkness(const std::string& eternalId) {
    EternalVoid::EternalVoidEngine::DescendIntoDarkness(eternalId, 0.1f);
}

void EternalVoidPanel::OnCreateVacancy(const std::string& emptinessId) {
    EternalVoid::EternalVoidEngine::CreateVacancy(emptinessId, 0.1f);
}

void EternalVoidPanel::OnDeepenHollowness(const std::string& emptinessId) {
    EternalVoid::EternalVoidEngine::DeepenHollowness(emptinessId, 0.1f);
}

void EternalVoidPanel::OnDeclareEmpty(const std::string& emptinessId) {
    EternalVoid::EternalVoidEngine::DeclareEmpty(emptinessId);
}

void EternalVoidPanel::OnEmbraceNullity(const std::string& nothingnessId) {
    EternalVoid::EternalVoidEngine::EmbraceNullity(nothingnessId, 0.1f);
}

void EternalVoidPanel::OnExpandVoidness(const std::string& nothingnessId) {
    EternalVoid::EternalVoidEngine::ExpandVoidness(nothingnessId, 0.1f);
}

void EternalVoidPanel::OnDeclareNothing(const std::string& nothingnessId) {
    EternalVoid::EternalVoidEngine::DeclareNothing(nothingnessId);
}

void EternalVoidPanel::OnCultivateQuietude(const std::string& silenceId) {
    EternalVoid::EternalVoidEngine::CultivateQuietude(silenceId, 0.1f);
}

void EternalVoidPanel::OnDeepenMuteness(const std::string& silenceId) {
    EternalVoid::EternalVoidEngine::DeepenMuteness(silenceId, 0.1f);
}

void EternalVoidPanel::OnDeclareSilent(const std::string& silenceId) {
    EternalVoid::EternalVoidEngine::DeclareSilent(silenceId);
}

void EternalVoidPanel::OnAchieveMotionlessness(const std::string& stillnessId) {
    EternalVoid::EternalVoidEngine::AchieveMotionlessness(stillnessId, 0.1f);
}

void EternalVoidPanel::OnCultivateCalmness(const std::string& stillnessId) {
    EternalVoid::EternalVoidEngine::CultivateCalmness(stillnessId, 0.1f);
}

void EternalVoidPanel::OnDeclareStill(const std::string& stillnessId) {
    EternalVoid::EternalVoidEngine::DeclareStill(stillnessId);
}

void EternalVoidPanel::OnDeepenObscurity(const std::string& darknessId) {
    EternalVoid::EternalVoidEngine::DeepenObscurity(darknessId, 0.1f);
}

void EternalVoidPanel::OnExtendShadow(const std::string& darknessId) {
    EternalVoid::EternalVoidEngine::ExtendShadow(darknessId, 0.1f);
}

void EternalVoidPanel::OnDeclareDark(const std::string& darknessId) {
    EternalVoid::EternalVoidEngine::DeclareDark(darknessId);
}

} // namespace IDE
