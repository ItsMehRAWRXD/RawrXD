#include "AbsoluteTruthPanel.hpp"
#include "../infinite/AbsoluteTruthEngine.hpp"
#include "../infinite/AbsoluteTruthLoop.hpp"
#include <imgui.h>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace IDE {

AbsoluteTruthPanel::AbsoluteTruthPanel()
    : m_initialized(false)
    , m_visible(false)
    , m_currentTab(0)
{
    ClearInputBuffers();
    std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
}

AbsoluteTruthPanel::~AbsoluteTruthPanel() {
    Shutdown();
}

bool AbsoluteTruthPanel::Initialize() {
    if (m_initialized) return true;
    
    if (!AbsoluteTruth::AbsoluteTruthEngine::Initialize()) {
        return false;
    }
    
    AbsoluteTruth::AbsoluteTruthLoopConfig loopConfig;
    loopConfig.targetTPS = 60;
    loopConfig.maxFPS = 60;
    loopConfig.enableFrameLimiting = true;
    loopConfig.enableMetrics = true;
    
    if (!AbsoluteTruth::AbsoluteTruthLoop::Init(loopConfig)) {
        return false;
    }
    
    m_initialized = true;
    return true;
}

void AbsoluteTruthPanel::Shutdown() {
    if (!m_initialized) return;
    
    AbsoluteTruth::AbsoluteTruthLoop::Shutdown();
    AbsoluteTruth::AbsoluteTruthEngine::Shutdown();
    
    m_initialized = false;
}

bool AbsoluteTruthPanel::IsInitialized() const {
    return m_initialized;
}

void AbsoluteTruthPanel::Show() {
    m_visible = true;
}

void AbsoluteTruthPanel::Hide() {
    m_visible = false;
}

void AbsoluteTruthPanel::ToggleVisibility() {
    m_visible = !m_visible;
}

bool AbsoluteTruthPanel::IsVisible() const {
    return m_visible;
}

void AbsoluteTruthPanel::Render() {
    if (!m_visible || !m_initialized) return;
    RenderWindow();
}

void AbsoluteTruthPanel::RenderWindow() {
    ImGui::SetNextWindowSize(ImVec2(900, 700), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Absolute Truth (Layer 117)", &m_visible)) {
        RenderTabBar();
        
        switch (static_cast<Tab>(m_currentTab)) {
            case Tab::TruthStructures:
                RenderTruthStructuresTab();
                break;
            case Tab::VerityAbsolutes:
                RenderVerityAbsolutesTab();
                break;
            case Tab::FactAbsolutes:
                RenderFactAbsolutesTab();
                break;
            case Tab::RealityAbsolutes:
                RenderRealityAbsolutesTab();
                break;
            case Tab::ActualityAbsolutes:
                RenderActualityAbsolutesTab();
                break;
            case Tab::CertaintyAbsolutes:
                RenderCertaintyAbsolutesTab();
                break;
            case Tab::ValidityAbsolutes:
                RenderValidityAbsolutesTab();
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

void AbsoluteTruthPanel::RenderTabBar() {
    if (ImGui::BeginTabBar("AbsoluteTruthTabs")) {
        if (ImGui::BeginTabItem("Truth Structures")) {
            m_currentTab = static_cast<int>(Tab::TruthStructures);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Verity Absolutes")) {
            m_currentTab = static_cast<int>(Tab::VerityAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Fact Absolutes")) {
            m_currentTab = static_cast<int>(Tab::FactAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Reality Absolutes")) {
            m_currentTab = static_cast<int>(Tab::RealityAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Actuality Absolutes")) {
            m_currentTab = static_cast<int>(Tab::ActualityAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Certainty Absolutes")) {
            m_currentTab = static_cast<int>(Tab::CertaintyAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Validity Absolutes")) {
            m_currentTab = static_cast<int>(Tab::ValidityAbsolutes);
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

void AbsoluteTruthPanel::RenderTruthStructuresTab() {
    ImGui::Text("Absolute Truth Structures");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name", m_newTruthName, sizeof(m_newTruthName));
    ImGui::SameLine();
    if (ImGui::Button("Create")) {
        CreateNewAbsoluteTruthStructure();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto truthIds = AbsoluteTruth::AbsoluteTruthEngine::GetAllAbsoluteTruthStructureIds();
    
    ImGui::BeginChild("TruthList", ImVec2(300, 0), true);
    for (const auto& id : truthIds) {
        auto truth = AbsoluteTruth::AbsoluteTruthEngine::GetAbsoluteTruthStructure(id);
        if (truth && FilterMatches(truth->name)) {
            bool isSelected = (m_selectedTruthId == id);
            if (ImGui::Selectable(truth->name.c_str(), isSelected)) {
                SelectAbsoluteTruthStructure(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("TruthDetails", ImVec2(0, 0), true);
    if (!m_selectedTruthId.empty()) {
        RenderAbsoluteTruthStructureDetails(m_selectedTruthId);
    } else {
        ImGui::Text("Select an absolute truth structure to view details");
    }
    ImGui::EndChild();
}

void AbsoluteTruthPanel::RenderVerityAbsolutesTab() {
    ImGui::Text("Verity Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Verity", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Verity")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Verity", m_newVerityName, sizeof(m_newVerityName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Verity")) {
        CreateNewVerityAbsolute();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto verityIds = AbsoluteTruth::AbsoluteTruthEngine::GetAllVerityAbsoluteIds();
    
    ImGui::BeginChild("VerityList", ImVec2(300, 0), true);
    for (const auto& id : verityIds) {
        auto verity = AbsoluteTruth::AbsoluteTruthEngine::GetVerityAbsolute(id);
        if (verity && FilterMatches(verity->name)) {
            bool isSelected = (m_selectedVerityId == id);
            if (ImGui::Selectable(verity->name.c_str(), isSelected)) {
                SelectVerityAbsolute(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("VerityDetails", ImVec2(0, 0), true);
    if (!m_selectedVerityId.empty()) {
        RenderVerityAbsoluteDetails(m_selectedVerityId);
    } else {
        ImGui::Text("Select a verity absolute to view details");
    }
    ImGui::EndChild();
}

void AbsoluteTruthPanel::RenderFactAbsolutesTab() {
    ImGui::Text("Fact Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Fact", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Fact")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Fact", m_newFactName, sizeof(m_newFactName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Fact")) {
        CreateNewFactAbsolute();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto factIds = AbsoluteTruth::AbsoluteTruthEngine::GetAllFactAbsoluteIds();
    
    ImGui::BeginChild("FactList", ImVec2(300, 0), true);
    for (const auto& id : factIds) {
        auto fact = AbsoluteTruth::AbsoluteTruthEngine::GetFactAbsolute(id);
        if (fact && FilterMatches(fact->name)) {
            bool isSelected = (m_selectedFactId == id);
            if (ImGui::Selectable(fact->name.c_str(), isSelected)) {
                SelectFactAbsolute(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("FactDetails", ImVec2(0, 0), true);
    if (!m_selectedFactId.empty()) {
        RenderFactAbsoluteDetails(m_selectedFactId);
    } else {
        ImGui::Text("Select a fact absolute to view details");
    }
    ImGui::EndChild();
}

void AbsoluteTruthPanel::RenderRealityAbsolutesTab() {
    ImGui::Text("Reality Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Reality", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Reality")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Reality", m_newRealityName, sizeof(m_newRealityName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Reality")) {
        CreateNewRealityAbsolute();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto realityIds = AbsoluteTruth::AbsoluteTruthEngine::GetAllRealityAbsoluteIds();
    
    ImGui::BeginChild("RealityList", ImVec2(300, 0), true);
    for (const auto& id : realityIds) {
        auto reality = AbsoluteTruth::AbsoluteTruthEngine::GetRealityAbsolute(id);
        if (reality && FilterMatches(reality->name)) {
            bool isSelected = (m_selectedRealityId == id);
            if (ImGui::Selectable(reality->name.c_str(), isSelected)) {
                SelectRealityAbsolute(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("RealityDetails", ImVec2(0, 0), true);
    if (!m_selectedRealityId.empty()) {
        RenderRealityAbsoluteDetails(m_selectedRealityId);
    } else {
        ImGui::Text("Select a reality absolute to view details");
    }
    ImGui::EndChild();
}

void AbsoluteTruthPanel::RenderActualityAbsolutesTab() {
    ImGui::Text("Actuality Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Actuality", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Actuality")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Actuality", m_newActualityName, sizeof(m_newActualityName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Actuality")) {
        CreateNewActualityAbsolute();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto actualityIds = AbsoluteTruth::AbsoluteTruthEngine::GetAllActualityAbsoluteIds();
    
    ImGui::BeginChild("ActualityList", ImVec2(300, 0), true);
    for (const auto& id : actualityIds) {
        auto actuality = AbsoluteTruth::AbsoluteTruthEngine::GetActualityAbsolute(id);
        if (actuality && FilterMatches(actuality->name)) {
            bool isSelected = (m_selectedActualityId == id);
            if (ImGui::Selectable(actuality->name.c_str(), isSelected)) {
                SelectActualityAbsolute(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("ActualityDetails", ImVec2(0, 0), true);
    if (!m_selectedActualityId.empty()) {
        RenderActualityAbsoluteDetails(m_selectedActualityId);
    } else {
        ImGui::Text("Select an actuality absolute to view details");
    }
    ImGui::EndChild();
}

void AbsoluteTruthPanel::RenderCertaintyAbsolutesTab() {
    ImGui::Text("Certainty Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Certainty", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Certainty")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Certainty", m_newCertaintyName, sizeof(m_newCertaintyName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Certainty")) {
        CreateNewCertaintyAbsolute();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto certaintyIds = AbsoluteTruth::AbsoluteTruthEngine::GetAllCertaintyAbsoluteIds();
    
    ImGui::BeginChild("CertaintyList", ImVec2(300, 0), true);
    for (const auto& id : certaintyIds) {
        auto certainty = AbsoluteTruth::AbsoluteTruthEngine::GetCertaintyAbsolute(id);
        if (certainty && FilterMatches(certainty->name)) {
            bool isSelected = (m_selectedCertaintyId == id);
            if (ImGui::Selectable(certainty->name.c_str(), isSelected)) {
                SelectCertaintyAbsolute(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("CertaintyDetails", ImVec2(0, 0), true);
    if (!m_selectedCertaintyId.empty()) {
        RenderCertaintyAbsoluteDetails(m_selectedCertaintyId);
    } else {
        ImGui::Text("Select a certainty absolute to view details");
    }
    ImGui::EndChild();
}

void AbsoluteTruthPanel::RenderValidityAbsolutesTab() {
    ImGui::Text("Validity Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Validity", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Validity")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Validity", m_newValidityName, sizeof(m_newValidityName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Validity")) {
        CreateNewValidityAbsolute();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto validityIds = AbsoluteTruth::AbsoluteTruthEngine::GetAllValidityAbsoluteIds();
    
    ImGui::BeginChild("ValidityList", ImVec2(300, 0), true);
    for (const auto& id : validityIds) {
        auto validity = AbsoluteTruth::AbsoluteTruthEngine::GetValidityAbsolute(id);
        if (validity && FilterMatches(validity->name)) {
            bool isSelected = (m_selectedValidityId == id);
            if (ImGui::Selectable(validity->name.c_str(), isSelected)) {
                SelectValidityAbsolute(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("ValidityDetails", ImVec2(0, 0), true);
    if (!m_selectedValidityId.empty()) {
        RenderValidityAbsoluteDetails(m_selectedValidityId);
    } else {
        ImGui::Text("Select a validity absolute to view details");
    }
    ImGui::EndChild();
}

void AbsoluteTruthPanel::RenderMetricsTab() {
    ImGui::Text("Absolute Truth Metrics");
    ImGui::Separator();
    
    auto metrics = AbsoluteTruth::AbsoluteTruthLoop::GetMetrics();
    
    ImGui::Text("Performance Metrics:");
    DrawMetric("Current TPS", metrics.currentTPS, "%.1f");
    DrawMetric("Current FPS", metrics.currentFPS, "%.1f");
    DrawMetric("Average Tick Time (ms)", metrics.averageTickTimeMs, "%.3f");
    DrawMetric("Average Frame Time (ms)", metrics.averageFrameTimeMs, "%.3f");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Counters:");
    ImGui::Text("Total Ticks: %lld", metrics.totalTicks);
    ImGui::Text("Total Frames: %lld", metrics.totalFrames);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Engine Statistics:");
    ImGui::Text("Truth Structures: %zu", AbsoluteTruth::AbsoluteTruthEngine::GetAllAbsoluteTruthStructureIds().size());
    ImGui::Text("Verity Absolutes: %zu", AbsoluteTruth::AbsoluteTruthEngine::GetAllVerityAbsoluteIds().size());
    ImGui::Text("Fact Absolutes: %zu", AbsoluteTruth::AbsoluteTruthEngine::GetAllFactAbsoluteIds().size());
    ImGui::Text("Reality Absolutes: %zu", AbsoluteTruth::AbsoluteTruthEngine::GetAllRealityAbsoluteIds().size());
    ImGui::Text("Actuality Absolutes: %zu", AbsoluteTruth::AbsoluteTruthEngine::GetAllActualityAbsoluteIds().size());
    ImGui::Text("Certainty Absolutes: %zu", AbsoluteTruth::AbsoluteTruthEngine::GetAllCertaintyAbsoluteIds().size());
    ImGui::Text("Validity Absolutes: %zu", AbsoluteTruth::AbsoluteTruthEngine::GetAllValidityAbsoluteIds().size());
}

void AbsoluteTruthPanel::RenderSettingsTab() {
    ImGui::Text("Absolute Truth Settings");
    ImGui::Separator();
    
    auto config = AbsoluteTruth::AbsoluteTruthLoop::GetConfig();
    
    bool changed = false;
    
    changed |= ImGui::InputInt("Target TPS", &config.targetTPS);
    changed |= ImGui::InputInt("Max FPS", &config.maxFPS);
    changed |= ImGui::Checkbox("Enable Frame Limiting", &config.enableFrameLimiting);
    changed |= ImGui::Checkbox("Enable Metrics", &config.enableMetrics);
    
    if (changed) {
        AbsoluteTruth::AbsoluteTruthLoop::SetConfig(config);
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Loop Control:");
    
    if (AbsoluteTruth::AbsoluteTruthLoop::IsRunning()) {
        if (ImGui::Button("Stop Loop")) {
            AbsoluteTruth::AbsoluteTruthLoop::Stop();
        }
        ImGui::SameLine();
        if (AbsoluteTruth::AbsoluteTruthLoop::IsPaused()) {
            if (ImGui::Button("Resume")) {
                AbsoluteTruth::AbsoluteTruthLoop::Resume();
            }
        } else {
            if (ImGui::Button("Pause")) {
                AbsoluteTruth::AbsoluteTruthLoop::Pause();
            }
        }
    } else {
        if (ImGui::Button("Start Loop")) {
            AbsoluteTruth::AbsoluteTruthLoop::Start();
        }
    }
}

void AbsoluteTruthPanel::RenderAbsoluteTruthStructureDetails(const std::string& truthId) {
    auto truth = AbsoluteTruth::AbsoluteTruthEngine::GetAbsoluteTruthStructure(truthId);
    if (!truth) return;
    
    ImGui::Text("Name: %s", truth->name.c_str());
    ImGui::Text("ID: %s", truth->id.c_str());
    ImGui::Text("Created: %s", truth->createdAt.c_str());
    ImGui::Text("Modified: %s", truth->modifiedAt.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Verity", truth->verity);
    DrawMetric("Factuality", truth->factuality);
    DrawMetric("Reality", truth->reality);
    DrawMetric("Actuality", truth->actuality);
    DrawMetric("Certainty", truth->certainty);
    DrawMetric("Validity", truth->validity);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Expand Absolute Truth")) {
        OnExpandAbsoluteTruth(truthId);
    }
    if (ImGui::Button("Amplify Verity")) {
        OnAmplifyVerity(truthId);
    }
    if (ImGui::Button("Increase Factuality")) {
        OnIncreaseFactuality(truthId);
    }
    if (ImGui::Button("Enhance Reality")) {
        OnEnhanceReality(truthId);
    }
    if (ImGui::Button("Solidify Actuality")) {
        OnSolidifyActuality(truthId);
    }
    if (ImGui::Button("Strengthen Certainty")) {
        OnStrengthenCertainty(truthId);
    }
    if (ImGui::Button("Validate Absolute")) {
        OnValidateAbsolute(truthId);
    }
}

void AbsoluteTruthPanel::RenderVerityAbsoluteDetails(const std::string& verityId) {
    auto verity = AbsoluteTruth::AbsoluteTruthEngine::GetVerityAbsolute(verityId);
    if (!verity) return;
    
    ImGui::Text("Name: %s", verity->name.c_str());
    ImGui::Text("ID: %s", verity->id.c_str());
    ImGui::Text("Is Absolute: %s", verity->isAbsolute ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Verity", verity->verity);
    DrawMetric("Factuality", verity->factuality);
    DrawMetric("Reality", verity->reality);
    DrawMetric("Actuality", verity->actuality);
    DrawMetric("Certainty", verity->certainty);
    DrawMetric("Validity", verity->validity);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Intensify Verity Absolute")) {
        OnIntensifyVerityAbsolute(verityId);
    }
    if (ImGui::Button("Affirm Verity Absolute")) {
        OnAffirmVerityAbsolute(verityId);
    }
    if (ImGui::Button("Declare Verity Absolute")) {
        OnDeclareVerityAbsolute(verityId);
    }
}

void AbsoluteTruthPanel::RenderFactAbsoluteDetails(const std::string& factId) {
    auto fact = AbsoluteTruth::AbsoluteTruthEngine::GetFactAbsolute(factId);
    if (!fact) return;
    
    ImGui::Text("Name: %s", fact->name.c_str());
    ImGui::Text("ID: %s", fact->id.c_str());
    ImGui::Text("Is Absolute: %s", fact->isAbsolute ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Verity", fact->verity);
    DrawMetric("Factuality", fact->factuality);
    DrawMetric("Reality", fact->reality);
    DrawMetric("Actuality", fact->actuality);
    DrawMetric("Certainty", fact->certainty);
    DrawMetric("Validity", fact->validity);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Verify Fact Absolute")) {
        OnVerifyFactAbsolute(factId);
    }
    if (ImGui::Button("Establish Fact Absolute")) {
        OnEstablishFactAbsolute(factId);
    }
    if (ImGui::Button("Declare Fact Absolute")) {
        OnDeclareFactAbsolute(factId);
    }
}

void AbsoluteTruthPanel::RenderRealityAbsoluteDetails(const std::string& realityId) {
    auto reality = AbsoluteTruth::AbsoluteTruthEngine::GetRealityAbsolute(realityId);
    if (!reality) return;
    
    ImGui::Text("Name: %s", reality->name.c_str());
    ImGui::Text("ID: %s", reality->id.c_str());
    ImGui::Text("Is Absolute: %s", reality->isAbsolute ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Verity", reality->verity);
    DrawMetric("Factuality", reality->factuality);
    DrawMetric("Reality", reality->reality);
    DrawMetric("Actuality", reality->actuality);
    DrawMetric("Certainty", reality->certainty);
    DrawMetric("Validity", reality->validity);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Manifest Reality Absolute")) {
        OnManifestRealityAbsolute(realityId);
    }
    if (ImGui::Button("Ground Reality Absolute")) {
        OnGroundRealityAbsolute(realityId);
    }
    if (ImGui::Button("Declare Reality Absolute")) {
        OnDeclareRealityAbsolute(realityId);
    }
}

void AbsoluteTruthPanel::RenderActualityAbsoluteDetails(const std::string& actualityId) {
    auto actuality = AbsoluteTruth::AbsoluteTruthEngine::GetActualityAbsolute(actualityId);
    if (!actuality) return;
    
    ImGui::Text("Name: %s", actuality->name.c_str());
    ImGui::Text("ID: %s", actuality->id.c_str());
    ImGui::Text("Is Absolute: %s", actuality->isAbsolute ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Verity", actuality->verity);
    DrawMetric("Factuality", actuality->factuality);
    DrawMetric("Reality", actuality->reality);
    DrawMetric("Actuality", actuality->actuality);
    DrawMetric("Certainty", actuality->certainty);
    DrawMetric("Validity", actuality->validity);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Realize Actuality Absolute")) {
        OnRealizeActualityAbsolute(actualityId);
    }
    if (ImGui::Button("Embody Actuality Absolute")) {
        OnEmbodyActualityAbsolute(actualityId);
    }
    if (ImGui::Button("Declare Actuality Absolute")) {
        OnDeclareActualityAbsolute(actualityId);
    }
}

void AbsoluteTruthPanel::RenderCertaintyAbsoluteDetails(const std::string& certaintyId) {
    auto certainty = AbsoluteTruth::AbsoluteTruthEngine::GetCertaintyAbsolute(certaintyId);
    if (!certainty) return;
    
    ImGui::Text("Name: %s", certainty->name.c_str());
    ImGui::Text("ID: %s", certainty->id.c_str());
    ImGui::Text("Is Absolute: %s", certainty->isAbsolute ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Verity", certainty->verity);
    DrawMetric("Factuality", certainty->factuality);
    DrawMetric("Reality", certainty->reality);
    DrawMetric("Actuality", certainty->actuality);
    DrawMetric("Certainty", certainty->certainty);
    DrawMetric("Validity", certainty->validity);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Guarantee Certainty Absolute")) {
        OnGuaranteeCertaintyAbsolute(certaintyId);
    }
    if (ImGui::Button("Secure Certainty Absolute")) {
        OnSecureCertaintyAbsolute(certaintyId);
    }
    if (ImGui::Button("Declare Certainty Absolute")) {
        OnDeclareCertaintyAbsolute(certaintyId);
    }
}

void AbsoluteTruthPanel::RenderValidityAbsoluteDetails(const std::string& validityId) {
    auto validity = AbsoluteTruth::AbsoluteTruthEngine::GetValidityAbsolute(validityId);
    if (!validity) return;
    
    ImGui::Text("Name: %s", validity->name.c_str());
    ImGui::Text("ID: %s", validity->id.c_str());
    ImGui::Text("Is Absolute: %s", validity->isAbsolute ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Verity", validity->verity);
    DrawMetric("Factuality", validity->factuality);
    DrawMetric("Reality", validity->reality);
    DrawMetric("Actuality", validity->actuality);
    DrawMetric("Certainty", validity->certainty);
    DrawMetric("Validity", validity->validity);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Confirm Validity Absolute")) {
        OnConfirmValidityAbsolute(validityId);
    }
    if (ImGui::Button("Authenticate Validity Absolute")) {
        OnAuthenticateValidityAbsolute(validityId);
    }
    if (ImGui::Button("Declare Validity Absolute")) {
        OnDeclareValidityAbsolute(validityId);
    }
}

void AbsoluteTruthPanel::SelectAbsoluteTruthStructure(const std::string& truthId) {
    m_selectedTruthId = truthId;
}

void AbsoluteTruthPanel::SelectVerityAbsolute(const std::string& verityId) {
    m_selectedVerityId = verityId;
}

void AbsoluteTruthPanel::SelectFactAbsolute(const std::string& factId) {
    m_selectedFactId = factId;
}

void AbsoluteTruthPanel::SelectRealityAbsolute(const std::string& realityId) {
    m_selectedRealityId = realityId;
}

void AbsoluteTruthPanel::SelectActualityAbsolute(const std::string& actualityId) {
    m_selectedActualityId = actualityId;
}

void AbsoluteTruthPanel::SelectCertaintyAbsolute(const std::string& certaintyId) {
    m_selectedCertaintyId = certaintyId;
}

void AbsoluteTruthPanel::SelectValidityAbsolute(const std::string& validityId) {
    m_selectedValidityId = validityId;
}

void AbsoluteTruthPanel::CreateNewAbsoluteTruthStructure() {
    if (std::strlen(m_newTruthName) > 0) {
        AbsoluteTruth::AbsoluteTruthEngine::CreateAbsoluteTruthStructure(m_newTruthName);
        std::memset(m_newTruthName, 0, sizeof(m_newTruthName));
    }
}

void AbsoluteTruthPanel::CreateNewVerityAbsolute() {
    if (std::strlen(m_newVerityName) > 0) {
        AbsoluteTruth::AbsoluteTruthEngine::CreateVerityAbsolute(m_newVerityName);
        std::memset(m_newVerityName, 0, sizeof(m_newVerityName));
    }
}

void AbsoluteTruthPanel::CreateNewFactAbsolute() {
    if (std::strlen(m_newFactName) > 0) {
        AbsoluteTruth::AbsoluteTruthEngine::CreateFactAbsolute(m_newFactName);
        std::memset(m_newFactName, 0, sizeof(m_newFactName));
    }
}

void AbsoluteTruthPanel::CreateNewRealityAbsolute() {
    if (std::strlen(m_newRealityName) > 0) {
        AbsoluteTruth::AbsoluteTruthEngine::CreateRealityAbsolute(m_newRealityName);
        std::memset(m_newRealityName, 0, sizeof(m_newRealityName));
    }
}

void AbsoluteTruthPanel::CreateNewActualityAbsolute() {
    if (std::strlen(m_newActualityName) > 0) {
        AbsoluteTruth::AbsoluteTruthEngine::CreateActualityAbsolute(m_newActualityName);
        std::memset(m_newActualityName, 0, sizeof(m_newActualityName));
    }
}

void AbsoluteTruthPanel::CreateNewCertaintyAbsolute() {
    if (std::strlen(m_newCertaintyName) > 0) {
        AbsoluteTruth::AbsoluteTruthEngine::CreateCertaintyAbsolute(m_newCertaintyName);
        std::memset(m_newCertaintyName, 0, sizeof(m_newCertaintyName));
    }
}

void AbsoluteTruthPanel::CreateNewValidityAbsolute() {
    if (std::strlen(m_newValidityName) > 0) {
        AbsoluteTruth::AbsoluteTruthEngine::CreateValidityAbsolute(m_newValidityName);
        std::memset(m_newValidityName, 0, sizeof(m_newValidityName));
    }
}

void AbsoluteTruthPanel::ClearInputBuffers() {
    std::memset(m_newTruthName, 0, sizeof(m_newTruthName));
    std::memset(m_newVerityName, 0, sizeof(m_newVerityName));
    std::memset(m_newFactName, 0, sizeof(m_newFactName));
    std::memset(m_newRealityName, 0, sizeof(m_newRealityName));
    std::memset(m_newActualityName, 0, sizeof(m_newActualityName));
    std::memset(m_newCertaintyName, 0, sizeof(m_newCertaintyName));
    std::memset(m_newValidityName, 0, sizeof(m_newValidityName));
}

bool AbsoluteTruthPanel::FilterMatches(const std::string& text) const {
    if (std::strlen(m_filterBuffer) == 0) return true;
    return text.find(m_filterBuffer) != std::string::npos;
}

void AbsoluteTruthPanel::DrawProgressBar(float value, const ImVec4& color) {
    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color);
    ImGui::ProgressBar(value, ImVec2(-1, 0), "");
    ImGui::PopStyleColor();
}

void AbsoluteTruthPanel::DrawMetric(const char* label, float value, const char* format) {
    ImGui::Text("%s: ", label);
    ImGui::SameLine();
    ImGui::Text(format, value);
}

// Action handlers
void AbsoluteTruthPanel::OnExpandAbsoluteTruth(const std::string& truthId) {
    AbsoluteTruth::AbsoluteTruthEngine::ExpandAbsoluteTruth(truthId);
}

void AbsoluteTruthPanel::OnAmplifyVerity(const std::string& truthId) {
    AbsoluteTruth::AbsoluteTruthEngine::AmplifyVerity(truthId);
}

void AbsoluteTruthPanel::OnIncreaseFactuality(const std::string& truthId) {
    AbsoluteTruth::AbsoluteTruthEngine::IncreaseFactuality(truthId);
}

void AbsoluteTruthPanel::OnEnhanceReality(const std::string& truthId) {
    AbsoluteTruth::AbsoluteTruthEngine::EnhanceReality(truthId);
}

void AbsoluteTruthPanel::OnSolidifyActuality(const std::string& truthId) {
    AbsoluteTruth::AbsoluteTruthEngine::SolidifyActuality(truthId);
}

void AbsoluteTruthPanel::OnStrengthenCertainty(const std::string& truthId) {
    AbsoluteTruth::AbsoluteTruthEngine::StrengthenCertainty(truthId);
}

void AbsoluteTruthPanel::OnValidateAbsolute(const std::string& truthId) {
    AbsoluteTruth::AbsoluteTruthEngine::ValidateAbsolute(truthId);
}

void AbsoluteTruthPanel::OnIntensifyVerityAbsolute(const std::string& verityId) {
    AbsoluteTruth::AbsoluteTruthEngine::IntensifyVerityAbsolute(verityId);
}

void AbsoluteTruthPanel::OnAffirmVerityAbsolute(const std::string& verityId) {
    AbsoluteTruth::AbsoluteTruthEngine::AffirmVerityAbsolute(verityId);
}

void AbsoluteTruthPanel::OnDeclareVerityAbsolute(const std::string& verityId) {
    AbsoluteTruth::AbsoluteTruthEngine::DeclareVerityAbsolute(verityId);
}

void AbsoluteTruthPanel::OnVerifyFactAbsolute(const std::string& factId) {
    AbsoluteTruth::AbsoluteTruthEngine::VerifyFactAbsolute(factId);
}

void AbsoluteTruthPanel::OnEstablishFactAbsolute(const std::string& factId) {
    AbsoluteTruth::AbsoluteTruthEngine::EstablishFactAbsolute(factId);
}

void AbsoluteTruthPanel::OnDeclareFactAbsolute(const std::string& factId) {
    AbsoluteTruth::AbsoluteTruthEngine::DeclareFactAbsolute(factId);
}

void AbsoluteTruthPanel::OnManifestRealityAbsolute(const std::string& realityId) {
    AbsoluteTruth::AbsoluteTruthEngine::ManifestRealityAbsolute(realityId);
}

void AbsoluteTruthPanel::OnGroundRealityAbsolute(const std::string& realityId) {
    AbsoluteTruth::AbsoluteTruthEngine::GroundRealityAbsolute(realityId);
}

void AbsoluteTruthPanel::OnDeclareRealityAbsolute(const std::string& realityId) {
    AbsoluteTruth::AbsoluteTruthEngine::DeclareRealityAbsolute(realityId);
}

void AbsoluteTruthPanel::OnRealizeActualityAbsolute(const std::string& actualityId) {
    AbsoluteTruth::AbsoluteTruthEngine::RealizeActualityAbsolute(actualityId);
}

void AbsoluteTruthPanel::OnEmbodyActualityAbsolute(const std::string& actualityId) {
    AbsoluteTruth::AbsoluteTruthEngine::EmbodyActualityAbsolute(actualityId);
}

void AbsoluteTruthPanel::OnDeclareActualityAbsolute(const std::string& actualityId) {
    AbsoluteTruth::AbsoluteTruthEngine::DeclareActualityAbsolute(actualityId);
}

void AbsoluteTruthPanel::OnGuaranteeCertaintyAbsolute(const std::string& certaintyId) {
    AbsoluteTruth::AbsoluteTruthEngine::GuaranteeCertaintyAbsolute(certaintyId);
}

void AbsoluteTruthPanel::OnSecureCertaintyAbsolute(const std::string& certaintyId) {
    AbsoluteTruth::AbsoluteTruthEngine::SecureCertaintyAbsolute(certaintyId);
}

void AbsoluteTruthPanel::OnDeclareCertaintyAbsolute(const std::string& certaintyId) {
    AbsoluteTruth::AbsoluteTruthEngine::DeclareCertaintyAbsolute(certaintyId);
}

void AbsoluteTruthPanel::OnConfirmValidityAbsolute(const std::string& validityId) {
    AbsoluteTruth::AbsoluteTruthEngine::ConfirmValidityAbsolute(validityId);
}

void AbsoluteTruthPanel::OnAuthenticateValidityAbsolute(const std::string& validityId) {
    AbsoluteTruth::AbsoluteTruthEngine::AuthenticateValidityAbsolute(validityId);
}

void AbsoluteTruthPanel::OnDeclareValidityAbsolute(const std::string& validityId) {
    AbsoluteTruth::AbsoluteTruthEngine::DeclareValidityAbsolute(validityId);
}

} // namespace IDE
