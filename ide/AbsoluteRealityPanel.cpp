#include "AbsoluteRealityPanel.hpp"
#include "../absolute/AbsoluteRealityEngine.hpp"
#include "../absolute/AbsoluteRealityLoop.hpp"
#include <imgui.h>
#include <algorithm>

namespace IDE {

AbsoluteRealityPanel::AbsoluteRealityPanel()
    : m_initialized(false)
    , m_visible(false)
    , m_currentTab(0)
{
    ClearInputBuffers();
    memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
}

AbsoluteRealityPanel::~AbsoluteRealityPanel() {
    if (m_initialized) {
        Shutdown();
    }
}

bool AbsoluteRealityPanel::Initialize() {
    if (m_initialized) return true;
    m_initialized = true;
    return true;
}

void AbsoluteRealityPanel::Shutdown() {
    if (!m_initialized) return;
    m_initialized = false;
}

bool AbsoluteRealityPanel::IsInitialized() const {
    return m_initialized;
}

void AbsoluteRealityPanel::Show() {
    m_visible = true;
}

void AbsoluteRealityPanel::Hide() {
    m_visible = false;
}

void AbsoluteRealityPanel::ToggleVisibility() {
    m_visible = !m_visible;
}

bool AbsoluteRealityPanel::IsVisible() const {
    return m_visible;
}

void AbsoluteRealityPanel::Render() {
    if (!m_visible || !m_initialized) return;
    RenderWindow();
}

void AbsoluteRealityPanel::RenderWindow() {
    ImGui::SetNextWindowSize(ImVec2(900, 700), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Absolute Reality (Layer 110)", &m_visible)) {
        RenderTabBar();
        
        switch (static_cast<Tab>(m_currentTab)) {
            case Tab::AbsoluteStructures:
                RenderAbsoluteStructuresTab();
                break;
            case Tab::RealityAbsolutes:
                RenderRealityAbsolutesTab();
                break;
            case Tab::TruthAbsolutes:
                RenderTruthAbsolutesTab();
                break;
            case Tab::ExistenceAbsolutes:
                RenderExistenceAbsolutesTab();
                break;
            case Tab::ActualityAbsolutes:
                RenderActualityAbsolutesTab();
                break;
            case Tab::SubstanceAbsolutes:
                RenderSubstanceAbsolutesTab();
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

void AbsoluteRealityPanel::RenderTabBar() {
    if (ImGui::BeginTabBar("AbsoluteRealityTabs")) {
        if (ImGui::BeginTabItem("Absolute Structures")) {
            m_currentTab = static_cast<int>(Tab::AbsoluteStructures);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Reality Absolutes")) {
            m_currentTab = static_cast<int>(Tab::RealityAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Truth Absolutes")) {
            m_currentTab = static_cast<int>(Tab::TruthAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Existence Absolutes")) {
            m_currentTab = static_cast<int>(Tab::ExistenceAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Actuality Absolutes")) {
            m_currentTab = static_cast<int>(Tab::ActualityAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Substance Absolutes")) {
            m_currentTab = static_cast<int>(Tab::SubstanceAbsolutes);
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

void AbsoluteRealityPanel::RenderAbsoluteStructuresTab() {
    ImGui::Text("Absolute Reality Structures");
    ImGui::Separator();
    
    // Filter
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewAbsoluteStructure();
    }
    
    ImGui::Spacing();
    
    // List
    auto structures = AbsoluteReality::AbsoluteRealityEngine::GetAllAbsoluteRealityStructures();
    
    if (ImGui::BeginTable("AbsoluteStructuresTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Absoluteness");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& structure : structures) {
            if (!FilterMatches(structure.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(structure.name.c_str(), m_selectedAbsoluteId == structure.absoluteId, 
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectAbsoluteStructure(structure.absoluteId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(structure.absoluteness);
            
            ImGui::TableSetColumnIndex(2);
            if (structure.isAbsolute) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "ABSOLUTE");
            } else if (structure.isActive) {
                ImGui::Text("Active");
            } else {
                ImGui::TextDisabled("Inactive");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(structure.absoluteId.c_str());
            if (ImGui::SmallButton("Expand")) {
                OnExpandAbsoluteness(structure.absoluteId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                AbsoluteReality::AbsoluteRealityEngine::DestroyAbsoluteRealityStructure(structure.absoluteId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    // Details
    if (!m_selectedAbsoluteId.empty()) {
        RenderAbsoluteStructureDetails(m_selectedAbsoluteId);
    }
}

void AbsoluteRealityPanel::RenderRealityAbsolutesTab() {
    ImGui::Text("Reality Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewRealityAbsolute();
    }
    
    ImGui::Spacing();
    
    auto realities = AbsoluteReality::AbsoluteRealityEngine::GetAllRealityAbsolutes();
    
    if (ImGui::BeginTable("RealityAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Reality");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& reality : realities) {
            if (!FilterMatches(reality.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(reality.name.c_str(), m_selectedRealityId == reality.realityId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectRealityAbsolute(reality.realityId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(reality.reality);
            
            ImGui::TableSetColumnIndex(2);
            if (reality.isReal) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "REAL");
            } else {
                ImGui::Text("Forming");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(reality.realityId.c_str());
            if (ImGui::SmallButton("Realize")) {
                OnRealizeActuality(reality.realityId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                AbsoluteReality::AbsoluteRealityEngine::DestroyRealityAbsolute(reality.realityId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedRealityId.empty()) {
        RenderRealityAbsoluteDetails(m_selectedRealityId);
    }
}

void AbsoluteRealityPanel::RenderTruthAbsolutesTab() {
    ImGui::Text("Truth Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewTruthAbsolute();
    }
    
    ImGui::Spacing();
    
    auto truths = AbsoluteReality::AbsoluteRealityEngine::GetAllTruthAbsolutes();
    
    if (ImGui::BeginTable("TruthAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Truth");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& truth : truths) {
            if (!FilterMatches(truth.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(truth.name.c_str(), m_selectedTruthId == truth.truthId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectTruthAbsolute(truth.truthId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(truth.truth);
            
            ImGui::TableSetColumnIndex(2);
            if (truth.isTrue) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "TRUE");
            } else {
                ImGui::Text("Verifying");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(truth.truthId.c_str());
            if (ImGui::SmallButton("Verify")) {
                OnVerifyVeracity(truth.truthId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                AbsoluteReality::AbsoluteRealityEngine::DestroyTruthAbsolute(truth.truthId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedTruthId.empty()) {
        RenderTruthAbsoluteDetails(m_selectedTruthId);
    }
}

void AbsoluteRealityPanel::RenderExistenceAbsolutesTab() {
    ImGui::Text("Existence Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewExistenceAbsolute();
    }
    
    ImGui::Spacing();
    
    auto existences = AbsoluteReality::AbsoluteRealityEngine::GetAllExistenceAbsolutes();
    
    if (ImGui::BeginTable("ExistenceAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Existence");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& existence : existences) {
            if (!FilterMatches(existence.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(existence.name.c_str(), m_selectedExistenceId == existence.existenceId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectExistenceAbsolute(existence.existenceId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(existence.existence);
            
            ImGui::TableSetColumnIndex(2);
            if (existence.isExisting) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "EXISTS");
            } else {
                ImGui::Text("Becoming");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(existence.existenceId.c_str());
            if (ImGui::SmallButton("Affirm")) {
                OnAffirmBeing(existence.existenceId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                AbsoluteReality::AbsoluteRealityEngine::DestroyExistenceAbsolute(existence.existenceId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedExistenceId.empty()) {
        RenderExistenceAbsoluteDetails(m_selectedExistenceId);
    }
}

void AbsoluteRealityPanel::RenderActualityAbsolutesTab() {
    ImGui::Text("Actuality Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewActualityAbsolute();
    }
    
    ImGui::Spacing();
    
    auto actualities = AbsoluteReality::AbsoluteRealityEngine::GetAllActualityAbsolutes();
    
    if (ImGui::BeginTable("ActualityAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Actuality");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& actuality : actualities) {
            if (!FilterMatches(actuality.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(actuality.name.c_str(), m_selectedActualityId == actuality.actualityId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectActualityAbsolute(actuality.actualityId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(actuality.actuality);
            
            ImGui::TableSetColumnIndex(2);
            if (actuality.isActual) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "ACTUAL");
            } else {
                ImGui::Text("Forming");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(actuality.actualityId.c_str());
            if (ImGui::SmallButton("Establish")) {
                OnEstablishFactuality(actuality.actualityId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                AbsoluteReality::AbsoluteRealityEngine::DestroyActualityAbsolute(actuality.actualityId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedActualityId.empty()) {
        RenderActualityAbsoluteDetails(m_selectedActualityId);
    }
}

void AbsoluteRealityPanel::RenderSubstanceAbsolutesTab() {
    ImGui::Text("Substance Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewSubstanceAbsolute();
    }
    
    ImGui::Spacing();
    
    auto substances = AbsoluteReality::AbsoluteRealityEngine::GetAllSubstanceAbsolutes();
    
    if (ImGui::BeginTable("SubstanceAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Substance");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& substance : substances) {
            if (!FilterMatches(substance.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(substance.name.c_str(), m_selectedSubstanceId == substance.substanceId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectSubstanceAbsolute(substance.substanceId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(substance.substance);
            
            ImGui::TableSetColumnIndex(2);
            if (substance.isSubstantial) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "SUBSTANTIAL");
            } else {
                ImGui::Text("Forming");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(substance.substanceId.c_str());
            if (ImGui::SmallButton("Deepen")) {
                OnDeepenEssence(substance.substanceId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                AbsoluteReality::AbsoluteRealityEngine::DestroySubstanceAbsolute(substance.substanceId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedSubstanceId.empty()) {
        RenderSubstanceAbsoluteDetails(m_selectedSubstanceId);
    }
}

void AbsoluteRealityPanel::RenderMetricsTab() {
    ImGui::Text("Absolute Reality Metrics");
    ImGui::Separator();
    
    auto metrics = AbsoluteReality::AbsoluteRealityEngine::GetAbsoluteRealityMetrics();
    auto loopMetrics = AbsoluteReality::AbsoluteRealityLoop::GetMetrics();
    
    ImGui::Columns(2, "MetricsColumns");
    
    ImGui::Text("Structures:");
    ImGui::Text("  Absolute Structures: %d", metrics.value("absoluteStructureCount", 0));
    ImGui::Text("  Reality Absolutes: %d", metrics.value("realityAbsoluteCount", 0));
    ImGui::Text("  Truth Absolutes: %d", metrics.value("truthAbsoluteCount", 0));
    ImGui::Text("  Existence Absolutes: %d", metrics.value("existenceAbsoluteCount", 0));
    ImGui::Text("  Actuality Absolutes: %d", metrics.value("actualityAbsoluteCount", 0));
    ImGui::Text("  Substance Absolutes: %d", metrics.value("substanceAbsoluteCount", 0));
    
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
    ImGui::Text("Absolute Values:");
    
    float totalAbsoluteness = metrics.value("totalAbsoluteness", 0.0f);
    float totalReality = metrics.value("totalReality", 0.0f);
    float totalTruth = metrics.value("totalTruth", 0.0f);
    float totalExistence = metrics.value("totalExistence", 0.0f);
    float totalActuality = metrics.value("totalActuality", 0.0f);
    float totalSubstance = metrics.value("totalSubstance", 0.0f);
    
    ImGui::Text("Total Absoluteness: %.2f", totalAbsoluteness);
    ImGui::Text("Total Reality: %.2f", totalReality);
    ImGui::Text("Total Truth: %.2f", totalTruth);
    ImGui::Text("Total Existence: %.2f", totalExistence);
    ImGui::Text("Total Actuality: %.2f", totalActuality);
    ImGui::Text("Total Substance: %.2f", totalSubstance);
}

void AbsoluteRealityPanel::RenderSettingsTab() {
    ImGui::Text("Absolute Reality Settings");
    ImGui::Separator();
    
    auto config = AbsoluteReality::AbsoluteRealityLoop::GetConfig();
    
    ImGui::SliderInt("Target TPS", &config.targetTPS, 1, 120);
    ImGui::SliderInt("Max FPS", &config.maxFPS, 1, 240);
    ImGui::Checkbox("Enable Frame Limiting", &config.enableFrameLimiting);
    ImGui::Checkbox("Enable Metrics", &config.enableMetrics);
    
    if (ImGui::Button("Apply Settings")) {
        AbsoluteReality::AbsoluteRealityLoop::SetConfig(config);
    }
}

void AbsoluteRealityPanel::RenderAbsoluteStructureDetails(const std::string& absoluteId) {
    auto structure = AbsoluteReality::AbsoluteRealityEngine::GetAbsoluteRealityStructure(absoluteId);
    if (!structure) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", structure->name.c_str());
    
    ImGui::Text("Absoluteness: %.2f", structure->absoluteness);
    ImGui::ProgressBar(structure->absoluteness);
    
    ImGui::Text("Reality: %.2f", structure->reality);
    ImGui::ProgressBar(structure->reality);
    
    ImGui::Text("Truth: %.2f", structure->truth);
    ImGui::ProgressBar(structure->truth);
    
    ImGui::Text("Existence: %.2f", structure->existence);
    ImGui::ProgressBar(structure->existence);
    
    ImGui::Text("Actuality: %.2f", structure->actuality);
    ImGui::ProgressBar(structure->actuality);
    
    ImGui::Text("Substance: %.2f", structure->substance);
    ImGui::ProgressBar(structure->substance);
    
    if (ImGui::Button("Expand Absoluteness")) OnExpandAbsoluteness(absoluteId);
    ImGui::SameLine();
    if (ImGui::Button("Deepen Reality")) OnDeepenReality(absoluteId);
    ImGui::SameLine();
    if (ImGui::Button("Reveal Truth")) OnRevealTruth(absoluteId);
    ImGui::SameLine();
    if (ImGui::Button("Affirm Existence")) OnAffirmExistence(absoluteId);
    ImGui::SameLine();
    if (ImGui::Button("Manifest Actuality")) OnManifestActuality(absoluteId);
    ImGui::SameLine();
    if (ImGui::Button("Solidify Substance")) OnSolidifySubstance(absoluteId);
}

void AbsoluteRealityPanel::RenderRealityAbsoluteDetails(const std::string& realityId) {
    auto reality = AbsoluteReality::AbsoluteRealityEngine::GetRealityAbsolute(realityId);
    if (!reality) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", reality->name.c_str());
    
    ImGui::Text("Reality: %.2f", reality->reality);
    ImGui::ProgressBar(reality->reality);
    
    ImGui::Text("Actuality: %.2f", reality->actuality);
    ImGui::ProgressBar(reality->actuality);
    
    ImGui::Text("Existence: %.2f", reality->existence);
    ImGui::ProgressBar(reality->existence);
    
    if (ImGui::Button("Realize Actuality")) OnRealizeActuality(realityId);
    ImGui::SameLine();
    if (ImGui::Button("Confirm Existence")) OnConfirmExistence(realityId);
    ImGui::SameLine();
    if (ImGui::Button("Declare Real")) OnDeclareReal(realityId);
}

void AbsoluteRealityPanel::RenderTruthAbsoluteDetails(const std::string& truthId) {
    auto truth = AbsoluteReality::AbsoluteRealityEngine::GetTruthAbsolute(truthId);
    if (!truth) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", truth->name.c_str());
    
    ImGui::Text("Truth: %.2f", truth->truth);
    ImGui::ProgressBar(truth->truth);
    
    ImGui::Text("Veracity: %.2f", truth->veracity);
    ImGui::ProgressBar(truth->veracity);
    
    ImGui::Text("Validity: %.2f", truth->validity);
    ImGui::ProgressBar(truth->validity);
    
    if (ImGui::Button("Verify Veracity")) OnVerifyVeracity(truthId);
    ImGui::SameLine();
    if (ImGui::Button("Validate Truth")) OnValidateTruth(truthId);
    ImGui::SameLine();
    if (ImGui::Button("Declare True")) OnDeclareTrue(truthId);
}

void AbsoluteRealityPanel::RenderExistenceAbsoluteDetails(const std::string& existenceId) {
    auto existence = AbsoluteReality::AbsoluteRealityEngine::GetExistenceAbsolute(existenceId);
    if (!existence) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", existence->name.c_str());
    
    ImGui::Text("Existence: %.2f", existence->existence);
    ImGui::ProgressBar(existence->existence);
    
    ImGui::Text("Being: %.2f", existence->being);
    ImGui::ProgressBar(existence->being);
    
    ImGui::Text("Presence: %.2f", existence->presence);
    ImGui::ProgressBar(existence->presence);
    
    if (ImGui::Button("Affirm Being")) OnAffirmBeing(existenceId);
    ImGui::SameLine();
    if (ImGui::Button("Manifest Presence")) OnManifestPresence(existenceId);
    ImGui::SameLine();
    if (ImGui::Button("Declare Existing")) OnDeclareExisting(existenceId);
}

void AbsoluteRealityPanel::RenderActualityAbsoluteDetails(const std::string& actualityId) {
    auto actuality = AbsoluteReality::AbsoluteRealityEngine::GetActualityAbsolute(actualityId);
    if (!actuality) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", actuality->name.c_str());
    
    ImGui::Text("Actuality: %.2f", actuality->actuality);
    ImGui::ProgressBar(actuality->actuality);
    
    ImGui::Text("Factuality: %.2f", actuality->factuality);
    ImGui::ProgressBar(actuality->factuality);
    
    ImGui::Text("Certainty: %.2f", actuality->certainty);
    ImGui::ProgressBar(actuality->certainty);
    
    if (ImGui::Button("Establish Factuality")) OnEstablishFactuality(actualityId);
    ImGui::SameLine();
    if (ImGui::Button("Ensure Certainty")) OnEnsureCertainty(actualityId);
    ImGui::SameLine();
    if (ImGui::Button("Declare Actual")) OnDeclareActual(actualityId);
}

void AbsoluteRealityPanel::RenderSubstanceAbsoluteDetails(const std::string& substanceId) {
    auto substance = AbsoluteReality::AbsoluteRealityEngine::GetSubstanceAbsolute(substanceId);
    if (!substance) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", substance->name.c_str());
    
    ImGui::Text("Substance: %.2f", substance->substance);
    ImGui::ProgressBar(substance->substance);
    
    ImGui::Text("Essence: %.2f", substance->essence);
    ImGui::ProgressBar(substance->essence);
    
    ImGui::Text("Matter: %.2f", substance->matter);
    ImGui::ProgressBar(substance->matter);
    
    if (ImGui::Button("Deepen Essence")) OnDeepenEssence(substanceId);
    ImGui::SameLine();
    if (ImGui::Button("Materialize Matter")) OnMaterializeMatter(substanceId);
    ImGui::SameLine();
    if (ImGui::Button("Declare Substantial")) OnDeclareSubstantial(substanceId);
}

void AbsoluteRealityPanel::SelectAbsoluteStructure(const std::string& absoluteId) {
    m_selectedAbsoluteId = absoluteId;
}

void AbsoluteRealityPanel::SelectRealityAbsolute(const std::string& realityId) {
    m_selectedRealityId = realityId;
}

void AbsoluteRealityPanel::SelectTruthAbsolute(const std::string& truthId) {
    m_selectedTruthId = truthId;
}

void AbsoluteRealityPanel::SelectExistenceAbsolute(const std::string& existenceId) {
    m_selectedExistenceId = existenceId;
}

void AbsoluteRealityPanel::SelectActualityAbsolute(const std::string& actualityId) {
    m_selectedActualityId = actualityId;
}

void AbsoluteRealityPanel::SelectSubstanceAbsolute(const std::string& substanceId) {
    m_selectedSubstanceId = substanceId;
}

void AbsoluteRealityPanel::CreateNewAbsoluteStructure() {
    ImGui::OpenPopup("Create Absolute Structure");
}

void AbsoluteRealityPanel::CreateNewRealityAbsolute() {
    AbsoluteReality::AbsoluteRealityEngine::CreateRealityAbsolute("New Reality Absolute");
}

void AbsoluteRealityPanel::CreateNewTruthAbsolute() {
    AbsoluteReality::AbsoluteRealityEngine::CreateTruthAbsolute("New Truth Absolute");
}

void AbsoluteRealityPanel::CreateNewExistenceAbsolute() {
    AbsoluteReality::AbsoluteRealityEngine::CreateExistenceAbsolute("New Existence Absolute");
}

void AbsoluteRealityPanel::CreateNewActualityAbsolute() {
    AbsoluteReality::AbsoluteRealityEngine::CreateActualityAbsolute("New Actuality Absolute");
}

void AbsoluteRealityPanel::CreateNewSubstanceAbsolute() {
    AbsoluteReality::AbsoluteRealityEngine::CreateSubstanceAbsolute("New Substance Absolute");
}

void AbsoluteRealityPanel::ClearInputBuffers() {
    memset(m_newAbsoluteName, 0, sizeof(m_newAbsoluteName));
    memset(m_newRealityName, 0, sizeof(m_newRealityName));
    memset(m_newTruthName, 0, sizeof(m_newTruthName));
    memset(m_newExistenceName, 0, sizeof(m_newExistenceName));
    memset(m_newActualityName, 0, sizeof(m_newActualityName));
    memset(m_newSubstanceName, 0, sizeof(m_newSubstanceName));
}

bool AbsoluteRealityPanel::FilterMatches(const std::string& text) const {
    if (strlen(m_filterBuffer) == 0) return true;
    return text.find(m_filterBuffer) != std::string::npos;
}

// Action handlers
void AbsoluteRealityPanel::OnExpandAbsoluteness(const std::string& absoluteId) {
    AbsoluteReality::AbsoluteRealityEngine::ExpandAbsoluteness(absoluteId, 0.1f);
}

void AbsoluteRealityPanel::OnDeepenReality(const std::string& absoluteId) {
    AbsoluteReality::AbsoluteRealityEngine::DeepenReality(absoluteId, 0.1f);
}

void AbsoluteRealityPanel::OnRevealTruth(const std::string& absoluteId) {
    AbsoluteReality::AbsoluteRealityEngine::RevealTruth(absoluteId, 0.1f);
}

void AbsoluteRealityPanel::OnAffirmExistence(const std::string& absoluteId) {
    AbsoluteReality::AbsoluteRealityEngine::AffirmExistence(absoluteId, 0.1f);
}

void AbsoluteRealityPanel::OnManifestActuality(const std::string& absoluteId) {
    AbsoluteReality::AbsoluteRealityEngine::ManifestActuality(absoluteId, 0.1f);
}

void AbsoluteRealityPanel::OnSolidifySubstance(const std::string& absoluteId) {
    AbsoluteReality::AbsoluteRealityEngine::SolidifySubstance(absoluteId, 0.1f);
}

void AbsoluteRealityPanel::OnRealizeActuality(const std::string& realityId) {
    AbsoluteReality::AbsoluteRealityEngine::RealizeActuality(realityId, 0.1f);
}

void AbsoluteRealityPanel::OnConfirmExistence(const std::string& realityId) {
    AbsoluteReality::AbsoluteRealityEngine::ConfirmExistence(realityId, 0.1f);
}

void AbsoluteRealityPanel::OnDeclareReal(const std::string& realityId) {
    AbsoluteReality::AbsoluteRealityEngine::DeclareReal(realityId);
}

void AbsoluteRealityPanel::OnVerifyVeracity(const std::string& truthId) {
    AbsoluteReality::AbsoluteRealityEngine::VerifyVeracity(truthId, 0.1f);
}

void AbsoluteRealityPanel::OnValidateTruth(const std::string& truthId) {
    AbsoluteReality::AbsoluteRealityEngine::ValidateTruth(truthId, 0.1f);
}

void AbsoluteRealityPanel::OnDeclareTrue(const std::string& truthId) {
    AbsoluteReality::AbsoluteRealityEngine::DeclareTrue(truthId);
}

void AbsoluteRealityPanel::OnAffirmBeing(const std::string& existenceId) {
    AbsoluteReality::AbsoluteRealityEngine::AffirmBeing(existenceId, 0.1f);
}

void AbsoluteRealityPanel::OnManifestPresence(const std::string& existenceId) {
    AbsoluteReality::AbsoluteRealityEngine::ManifestPresence(existenceId, 0.1f);
}

void AbsoluteRealityPanel::OnDeclareExisting(const std::string& existenceId) {
    AbsoluteReality::AbsoluteRealityEngine::DeclareExisting(existenceId);
}

void AbsoluteRealityPanel::OnEstablishFactuality(const std::string& actualityId) {
    AbsoluteReality::AbsoluteRealityEngine::EstablishFactuality(actualityId, 0.1f);
}

void AbsoluteRealityPanel::OnEnsureCertainty(const std::string& actualityId) {
    AbsoluteReality::AbsoluteRealityEngine::EnsureCertainty(actualityId, 0.1f);
}

void AbsoluteRealityPanel::OnDeclareActual(const std::string& actualityId) {
    AbsoluteReality::AbsoluteRealityEngine::DeclareActual(actualityId);
}

void AbsoluteRealityPanel::OnDeepenEssence(const std::string& substanceId) {
    AbsoluteReality::AbsoluteRealityEngine::DeepenEssence(substanceId, 0.1f);
}

void AbsoluteRealityPanel::OnMaterializeMatter(const std::string& substanceId) {
    AbsoluteReality::AbsoluteRealityEngine::MaterializeMatter(substanceId, 0.1f);
}

void AbsoluteRealityPanel::OnDeclareSubstantial(const std::string& substanceId) {
    AbsoluteReality::AbsoluteRealityEngine::DeclareSubstantial(substanceId);
}

} // namespace IDE
