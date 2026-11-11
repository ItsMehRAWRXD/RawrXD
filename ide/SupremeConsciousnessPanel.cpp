#include "SupremeConsciousnessPanel.hpp"
#include "../infinite/SupremeConsciousnessEngine.hpp"
#include "../infinite/SupremeConsciousnessLoop.hpp"
#include <imgui.h>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace IDE {

SupremeConsciousnessPanel::SupremeConsciousnessPanel()
    : m_initialized(false)
    , m_visible(false)
    , m_currentTab(0)
{
    ClearInputBuffers();
    std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
}

SupremeConsciousnessPanel::~SupremeConsciousnessPanel() {
    Shutdown();
}

bool SupremeConsciousnessPanel::Initialize() {
    if (m_initialized) return true;
    
    if (!SupremeConsciousness::SupremeConsciousnessEngine::Initialize()) {
        return false;
    }
    
    SupremeConsciousness::SupremeConsciousnessLoopConfig loopConfig;
    loopConfig.targetTPS = 60;
    loopConfig.maxFPS = 60;
    loopConfig.enableFrameLimiting = true;
    loopConfig.enableMetrics = true;
    
    if (!SupremeConsciousness::SupremeConsciousnessLoop::Init(loopConfig)) {
        return false;
    }
    
    m_initialized = true;
    return true;
}

void SupremeConsciousnessPanel::Shutdown() {
    if (!m_initialized) return;
    
    SupremeConsciousness::SupremeConsciousnessLoop::Shutdown();
    SupremeConsciousness::SupremeConsciousnessEngine::Shutdown();
    
    m_initialized = false;
}

bool SupremeConsciousnessPanel::IsInitialized() const {
    return m_initialized;
}

void SupremeConsciousnessPanel::Show() {
    m_visible = true;
}

void SupremeConsciousnessPanel::Hide() {
    m_visible = false;
}

void SupremeConsciousnessPanel::ToggleVisibility() {
    m_visible = !m_visible;
}

bool SupremeConsciousnessPanel::IsVisible() const {
    return m_visible;
}

void SupremeConsciousnessPanel::Render() {
    if (!m_visible || !m_initialized) return;
    RenderWindow();
}

void SupremeConsciousnessPanel::RenderWindow() {
    ImGui::SetNextWindowSize(ImVec2(900, 700), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Supreme Consciousness (Layer 116)", &m_visible)) {
        RenderTabBar();
        
        switch (static_cast<Tab>(m_currentTab)) {
            case Tab::SupremeStructures:
                RenderSupremeStructuresTab();
                break;
            case Tab::AwarenessSupremes:
                RenderAwarenessSupremesTab();
                break;
            case Tab::CognitionSupremes:
                RenderCognitionSupremesTab();
                break;
            case Tab::PerceptionSupremes:
                RenderPerceptionSupremesTab();
                break;
            case Tab::UnderstandingSupremes:
                RenderUnderstandingSupremesTab();
                break;
            case Tab::WisdomSupremes:
                RenderWisdomSupremesTab();
                break;
            case Tab::KnowledgeSupremes:
                RenderKnowledgeSupremesTab();
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

void SupremeConsciousnessPanel::RenderTabBar() {
    if (ImGui::BeginTabBar("SupremeConsciousnessTabs")) {
        if (ImGui::BeginTabItem("Supreme Structures")) {
            m_currentTab = static_cast<int>(Tab::SupremeStructures);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Awareness Supremes")) {
            m_currentTab = static_cast<int>(Tab::AwarenessSupremes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Cognition Supremes")) {
            m_currentTab = static_cast<int>(Tab::CognitionSupremes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Perception Supremes")) {
            m_currentTab = static_cast<int>(Tab::PerceptionSupremes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Understanding Supremes")) {
            m_currentTab = static_cast<int>(Tab::UnderstandingSupremes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Wisdom Supremes")) {
            m_currentTab = static_cast<int>(Tab::WisdomSupremes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Knowledge Supremes")) {
            m_currentTab = static_cast<int>(Tab::KnowledgeSupremes);
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

void SupremeConsciousnessPanel::RenderSupremeStructuresTab() {
    ImGui::Text("Supreme Consciousness Structures");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name", m_newSupremeName, sizeof(m_newSupremeName));
    ImGui::SameLine();
    if (ImGui::Button("Create")) {
        CreateNewSupremeConsciousnessStructure();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto supremeIds = SupremeConsciousness::SupremeConsciousnessEngine::GetAllSupremeConsciousnessStructureIds();
    
    ImGui::BeginChild("SupremeList", ImVec2(300, 0), true);
    for (const auto& id : supremeIds) {
        auto supreme = SupremeConsciousness::SupremeConsciousnessEngine::GetSupremeConsciousnessStructure(id);
        if (supreme && FilterMatches(supreme->name)) {
            bool isSelected = (m_selectedSupremeId == id);
            if (ImGui::Selectable(supreme->name.c_str(), isSelected)) {
                SelectSupremeConsciousnessStructure(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("SupremeDetails", ImVec2(0, 0), true);
    if (!m_selectedSupremeId.empty()) {
        RenderSupremeConsciousnessStructureDetails(m_selectedSupremeId);
    } else {
        ImGui::Text("Select a supreme consciousness structure to view details");
    }
    ImGui::EndChild();
}

void SupremeConsciousnessPanel::RenderAwarenessSupremesTab() {
    ImGui::Text("Awareness Supremes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Awareness", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Awareness")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Awareness", m_newAwarenessName, sizeof(m_newAwarenessName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Awareness")) {
        CreateNewAwarenessSupreme();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto awarenessIds = SupremeConsciousness::SupremeConsciousnessEngine::GetAllAwarenessSupremeIds();
    
    ImGui::BeginChild("AwarenessList", ImVec2(300, 0), true);
    for (const auto& id : awarenessIds) {
        auto awareness = SupremeConsciousness::SupremeConsciousnessEngine::GetAwarenessSupreme(id);
        if (awareness && FilterMatches(awareness->name)) {
            bool isSelected = (m_selectedAwarenessId == id);
            if (ImGui::Selectable(awareness->name.c_str(), isSelected)) {
                SelectAwarenessSupreme(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("AwarenessDetails", ImVec2(0, 0), true);
    if (!m_selectedAwarenessId.empty()) {
        RenderAwarenessSupremeDetails(m_selectedAwarenessId);
    } else {
        ImGui::Text("Select an awareness supreme to view details");
    }
    ImGui::EndChild();
}

void SupremeConsciousnessPanel::RenderCognitionSupremesTab() {
    ImGui::Text("Cognition Supremes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Cognition", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Cognition")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Cognition", m_newCognitionName, sizeof(m_newCognitionName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Cognition")) {
        CreateNewCognitionSupreme();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto cognitionIds = SupremeConsciousness::SupremeConsciousnessEngine::GetAllCognitionSupremeIds();
    
    ImGui::BeginChild("CognitionList", ImVec2(300, 0), true);
    for (const auto& id : cognitionIds) {
        auto cognition = SupremeConsciousness::SupremeConsciousnessEngine::GetCognitionSupreme(id);
        if (cognition && FilterMatches(cognition->name)) {
            bool isSelected = (m_selectedCognitionId == id);
            if (ImGui::Selectable(cognition->name.c_str(), isSelected)) {
                SelectCognitionSupreme(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("CognitionDetails", ImVec2(0, 0), true);
    if (!m_selectedCognitionId.empty()) {
        RenderCognitionSupremeDetails(m_selectedCognitionId);
    } else {
        ImGui::Text("Select a cognition supreme to view details");
    }
    ImGui::EndChild();
}

void SupremeConsciousnessPanel::RenderPerceptionSupremesTab() {
    ImGui::Text("Perception Supremes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Perception", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Perception")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Perception", m_newPerceptionName, sizeof(m_newPerceptionName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Perception")) {
        CreateNewPerceptionSupreme();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto perceptionIds = SupremeConsciousness::SupremeConsciousnessEngine::GetAllPerceptionSupremeIds();
    
    ImGui::BeginChild("PerceptionList", ImVec2(300, 0), true);
    for (const auto& id : perceptionIds) {
        auto perception = SupremeConsciousness::SupremeConsciousnessEngine::GetPerceptionSupreme(id);
        if (perception && FilterMatches(perception->name)) {
            bool isSelected = (m_selectedPerceptionId == id);
            if (ImGui::Selectable(perception->name.c_str(), isSelected)) {
                SelectPerceptionSupreme(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("PerceptionDetails", ImVec2(0, 0), true);
    if (!m_selectedPerceptionId.empty()) {
        RenderPerceptionSupremeDetails(m_selectedPerceptionId);
    } else {
        ImGui::Text("Select a perception supreme to view details");
    }
    ImGui::EndChild();
}

void SupremeConsciousnessPanel::RenderUnderstandingSupremesTab() {
    ImGui::Text("Understanding Supremes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Understanding", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Understanding")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Understanding", m_newUnderstandingName, sizeof(m_newUnderstandingName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Understanding")) {
        CreateNewUnderstandingSupreme();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto understandingIds = SupremeConsciousness::SupremeConsciousnessEngine::GetAllUnderstandingSupremeIds();
    
    ImGui::BeginChild("UnderstandingList", ImVec2(300, 0), true);
    for (const auto& id : understandingIds) {
        auto understanding = SupremeConsciousness::SupremeConsciousnessEngine::GetUnderstandingSupreme(id);
        if (understanding && FilterMatches(understanding->name)) {
            bool isSelected = (m_selectedUnderstandingId == id);
            if (ImGui::Selectable(understanding->name.c_str(), isSelected)) {
                SelectUnderstandingSupreme(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("UnderstandingDetails", ImVec2(0, 0), true);
    if (!m_selectedUnderstandingId.empty()) {
        RenderUnderstandingSupremeDetails(m_selectedUnderstandingId);
    } else {
        ImGui::Text("Select an understanding supreme to view details");
    }
    ImGui::EndChild();
}

void SupremeConsciousnessPanel::RenderWisdomSupremesTab() {
    ImGui::Text("Wisdom Supremes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Wisdom", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Wisdom")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Wisdom", m_newWisdomName, sizeof(m_newWisdomName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Wisdom")) {
        CreateNewWisdomSupreme();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto wisdomIds = SupremeConsciousness::SupremeConsciousnessEngine::GetAllWisdomSupremeIds();
    
    ImGui::BeginChild("WisdomList", ImVec2(300, 0), true);
    for (const auto& id : wisdomIds) {
        auto wisdom = SupremeConsciousness::SupremeConsciousnessEngine::GetWisdomSupreme(id);
        if (wisdom && FilterMatches(wisdom->name)) {
            bool isSelected = (m_selectedWisdomId == id);
            if (ImGui::Selectable(wisdom->name.c_str(), isSelected)) {
                SelectWisdomSupreme(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("WisdomDetails", ImVec2(0, 0), true);
    if (!m_selectedWisdomId.empty()) {
        RenderWisdomSupremeDetails(m_selectedWisdomId);
    } else {
        ImGui::Text("Select a wisdom supreme to view details");
    }
    ImGui::EndChild();
}

void SupremeConsciousnessPanel::RenderKnowledgeSupremesTab() {
    ImGui::Text("Knowledge Supremes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Knowledge", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Knowledge")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Knowledge", m_newKnowledgeName, sizeof(m_newKnowledgeName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Knowledge")) {
        CreateNewKnowledgeSupreme();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto knowledgeIds = SupremeConsciousness::SupremeConsciousnessEngine::GetAllKnowledgeSupremeIds();
    
    ImGui::BeginChild("KnowledgeList", ImVec2(300, 0), true);
    for (const auto& id : knowledgeIds) {
        auto knowledge = SupremeConsciousness::SupremeConsciousnessEngine::GetKnowledgeSupreme(id);
        if (knowledge && FilterMatches(knowledge->name)) {
            bool isSelected = (m_selectedKnowledgeId == id);
            if (ImGui::Selectable(knowledge->name.c_str(), isSelected)) {
                SelectKnowledgeSupreme(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("KnowledgeDetails", ImVec2(0, 0), true);
    if (!m_selectedKnowledgeId.empty()) {
        RenderKnowledgeSupremeDetails(m_selectedKnowledgeId);
    } else {
        ImGui::Text("Select a knowledge supreme to view details");
    }
    ImGui::EndChild();
}

void SupremeConsciousnessPanel::RenderMetricsTab() {
    ImGui::Text("Supreme Consciousness Metrics");
    ImGui::Separator();
    
    auto metrics = SupremeConsciousness::SupremeConsciousnessLoop::GetMetrics();
    
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
    ImGui::Text("Supreme Structures: %zu", SupremeConsciousness::SupremeConsciousnessEngine::GetAllSupremeConsciousnessStructureIds().size());
    ImGui::Text("Awareness Supremes: %zu", SupremeConsciousness::SupremeConsciousnessEngine::GetAllAwarenessSupremeIds().size());
    ImGui::Text("Cognition Supremes: %zu", SupremeConsciousness::SupremeConsciousnessEngine::GetAllCognitionSupremeIds().size());
    ImGui::Text("Perception Supremes: %zu", SupremeConsciousness::SupremeConsciousnessEngine::GetAllPerceptionSupremeIds().size());
    ImGui::Text("Understanding Supremes: %zu", SupremeConsciousness::SupremeConsciousnessEngine::GetAllUnderstandingSupremeIds().size());
    ImGui::Text("Wisdom Supremes: %zu", SupremeConsciousness::SupremeConsciousnessEngine::GetAllWisdomSupremeIds().size());
    ImGui::Text("Knowledge Supremes: %zu", SupremeConsciousness::SupremeConsciousnessEngine::GetAllKnowledgeSupremeIds().size());
}

void SupremeConsciousnessPanel::RenderSettingsTab() {
    ImGui::Text("Supreme Consciousness Settings");
    ImGui::Separator();
    
    auto config = SupremeConsciousness::SupremeConsciousnessLoop::GetConfig();
    
    bool changed = false;
    
    changed |= ImGui::InputInt("Target TPS", &config.targetTPS);
    changed |= ImGui::InputInt("Max FPS", &config.maxFPS);
    changed |= ImGui::Checkbox("Enable Frame Limiting", &config.enableFrameLimiting);
    changed |= ImGui::Checkbox("Enable Metrics", &config.enableMetrics);
    
    if (changed) {
        SupremeConsciousness::SupremeConsciousnessLoop::SetConfig(config);
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Loop Control:");
    
    if (SupremeConsciousness::SupremeConsciousnessLoop::IsRunning()) {
        if (ImGui::Button("Stop Loop")) {
            SupremeConsciousness::SupremeConsciousnessLoop::Stop();
        }
        ImGui::SameLine();
        if (SupremeConsciousness::SupremeConsciousnessLoop::IsPaused()) {
            if (ImGui::Button("Resume")) {
                SupremeConsciousness::SupremeConsciousnessLoop::Resume();
            }
        } else {
            if (ImGui::Button("Pause")) {
                SupremeConsciousness::SupremeConsciousnessLoop::Pause();
            }
        }
    } else {
        if (ImGui::Button("Start Loop")) {
            SupremeConsciousness::SupremeConsciousnessLoop::Start();
        }
    }
}

void SupremeConsciousnessPanel::RenderSupremeConsciousnessStructureDetails(const std::string& supremeId) {
    auto supreme = SupremeConsciousness::SupremeConsciousnessEngine::GetSupremeConsciousnessStructure(supremeId);
    if (!supreme) return;
    
    ImGui::Text("Name: %s", supreme->name.c_str());
    ImGui::Text("ID: %s", supreme->id.c_str());
    ImGui::Text("Created: %s", supreme->createdAt.c_str());
    ImGui::Text("Modified: %s", supreme->modifiedAt.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Awareness", supreme->awareness);
    DrawMetric("Cognition", supreme->cognition);
    DrawMetric("Perception", supreme->perception);
    DrawMetric("Understanding", supreme->understanding);
    DrawMetric("Wisdom", supreme->wisdom);
    DrawMetric("Knowledge", supreme->knowledge);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Expand Supreme Consciousness")) {
        OnExpandSupremeConsciousness(supremeId);
    }
    if (ImGui::Button("Amplify Awareness")) {
        OnAmplifyAwareness(supremeId);
    }
    if (ImGui::Button("Increase Cognition")) {
        OnIncreaseCognition(supremeId);
    }
    if (ImGui::Button("Enhance Perception")) {
        OnEnhancePerception(supremeId);
    }
    if (ImGui::Button("Deepen Understanding")) {
        OnDeepenUnderstanding(supremeId);
    }
    if (ImGui::Button("Cultivate Wisdom")) {
        OnCultivateWisdom(supremeId);
    }
    if (ImGui::Button("Accumulate Knowledge")) {
        OnAccumulateKnowledge(supremeId);
    }
}

void SupremeConsciousnessPanel::RenderAwarenessSupremeDetails(const std::string& awarenessId) {
    auto awareness = SupremeConsciousness::SupremeConsciousnessEngine::GetAwarenessSupreme(awarenessId);
    if (!awareness) return;
    
    ImGui::Text("Name: %s", awareness->name.c_str());
    ImGui::Text("ID: %s", awareness->id.c_str());
    ImGui::Text("Is Supreme: %s", awareness->isSupreme ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Awareness", awareness->awareness);
    DrawMetric("Cognition", awareness->cognition);
    DrawMetric("Perception", awareness->perception);
    DrawMetric("Understanding", awareness->understanding);
    DrawMetric("Wisdom", awareness->wisdom);
    DrawMetric("Knowledge", awareness->knowledge);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Intensify Awareness Supreme")) {
        OnIntensifyAwarenessSupreme(awarenessId);
    }
    if (ImGui::Button("Broaden Awareness Supreme")) {
        OnBroadenAwarenessSupreme(awarenessId);
    }
    if (ImGui::Button("Declare Awareness Supreme")) {
        OnDeclareAwarenessSupreme(awarenessId);
    }
}

void SupremeConsciousnessPanel::RenderCognitionSupremeDetails(const std::string& cognitionId) {
    auto cognition = SupremeConsciousness::SupremeConsciousnessEngine::GetCognitionSupreme(cognitionId);
    if (!cognition) return;
    
    ImGui::Text("Name: %s", cognition->name.c_str());
    ImGui::Text("ID: %s", cognition->id.c_str());
    ImGui::Text("Is Supreme: %s", cognition->isSupreme ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Awareness", cognition->awareness);
    DrawMetric("Cognition", cognition->cognition);
    DrawMetric("Perception", cognition->perception);
    DrawMetric("Understanding", cognition->understanding);
    DrawMetric("Wisdom", cognition->wisdom);
    DrawMetric("Knowledge", cognition->knowledge);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Sharpen Cognition Supreme")) {
        OnSharpenCognitionSupreme(cognitionId);
    }
    if (ImGui::Button("Expand Cognition Supreme")) {
        OnExpandCognitionSupreme(cognitionId);
    }
    if (ImGui::Button("Declare Cognition Supreme")) {
        OnDeclareCognitionSupreme(cognitionId);
    }
}

void SupremeConsciousnessPanel::RenderPerceptionSupremeDetails(const std::string& perceptionId) {
    auto perception = SupremeConsciousness::SupremeConsciousnessEngine::GetPerceptionSupreme(perceptionId);
    if (!perception) return;
    
    ImGui::Text("Name: %s", perception->name.c_str());
    ImGui::Text("ID: %s", perception->id.c_str());
    ImGui::Text("Is Supreme: %s", perception->isSupreme ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Awareness", perception->awareness);
    DrawMetric("Cognition", perception->cognition);
    DrawMetric("Perception", perception->perception);
    DrawMetric("Understanding", perception->understanding);
    DrawMetric("Wisdom", perception->wisdom);
    DrawMetric("Knowledge", perception->knowledge);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Refine Perception Supreme")) {
        OnRefinePerceptionSupreme(perceptionId);
    }
    if (ImGui::Button("Heighten Perception Supreme")) {
        OnHeightenPerceptionSupreme(perceptionId);
    }
    if (ImGui::Button("Declare Perception Supreme")) {
        OnDeclarePerceptionSupreme(perceptionId);
    }
}

void SupremeConsciousnessPanel::RenderUnderstandingSupremeDetails(const std::string& understandingId) {
    auto understanding = SupremeConsciousness::SupremeConsciousnessEngine::GetUnderstandingSupreme(understandingId);
    if (!understanding) return;
    
    ImGui::Text("Name: %s", understanding->name.c_str());
    ImGui::Text("ID: %s", understanding->id.c_str());
    ImGui::Text("Is Supreme: %s", understanding->isSupreme ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Awareness", understanding->awareness);
    DrawMetric("Cognition", understanding->cognition);
    DrawMetric("Perception", understanding->perception);
    DrawMetric("Understanding", understanding->understanding);
    DrawMetric("Wisdom", understanding->wisdom);
    DrawMetric("Knowledge", understanding->knowledge);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Deepen Understanding Supreme")) {
        OnDeepenUnderstandingSupreme(understandingId);
    }
    if (ImGui::Button("Clarify Understanding Supreme")) {
        OnClarifyUnderstandingSupreme(understandingId);
    }
    if (ImGui::Button("Declare Understanding Supreme")) {
        OnDeclareUnderstandingSupreme(understandingId);
    }
}

void SupremeConsciousnessPanel::RenderWisdomSupremeDetails(const std::string& wisdomId) {
    auto wisdom = SupremeConsciousness::SupremeConsciousnessEngine::GetWisdomSupreme(wisdomId);
    if (!wisdom) return;
    
    ImGui::Text("Name: %s", wisdom->name.c_str());
    ImGui::Text("ID: %s", wisdom->id.c_str());
    ImGui::Text("Is Supreme: %s", wisdom->isSupreme ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Awareness", wisdom->awareness);
    DrawMetric("Cognition", wisdom->cognition);
    DrawMetric("Perception", wisdom->perception);
    DrawMetric("Understanding", wisdom->understanding);
    DrawMetric("Wisdom", wisdom->wisdom);
    DrawMetric("Knowledge", wisdom->knowledge);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Cultivate Wisdom Supreme")) {
        OnCultivateWisdomSupreme(wisdomId);
    }
    if (ImGui::Button("Apply Wisdom Supreme")) {
        OnApplyWisdomSupreme(wisdomId);
    }
    if (ImGui::Button("Declare Wisdom Supreme")) {
        OnDeclareWisdomSupreme(wisdomId);
    }
}

void SupremeConsciousnessPanel::RenderKnowledgeSupremeDetails(const std::string& knowledgeId) {
    auto knowledge = SupremeConsciousness::SupremeConsciousnessEngine::GetKnowledgeSupreme(knowledgeId);
    if (!knowledge) return;
    
    ImGui::Text("Name: %s", knowledge->name.c_str());
    ImGui::Text("ID: %s", knowledge->id.c_str());
    ImGui::Text("Is Supreme: %s", knowledge->isSupreme ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Awareness", knowledge->awareness);
    DrawMetric("Cognition", knowledge->cognition);
    DrawMetric("Perception", knowledge->perception);
    DrawMetric("Understanding", knowledge->understanding);
    DrawMetric("Wisdom", knowledge->wisdom);
    DrawMetric("Knowledge", knowledge->knowledge);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Accumulate Knowledge Supreme")) {
        OnAccumulateKnowledgeSupreme(knowledgeId);
    }
    if (ImGui::Button("Organize Knowledge Supreme")) {
        OnOrganizeKnowledgeSupreme(knowledgeId);
    }
    if (ImGui::Button("Declare Knowledge Supreme")) {
        OnDeclareKnowledgeSupreme(knowledgeId);
    }
}

void SupremeConsciousnessPanel::SelectSupremeConsciousnessStructure(const std::string& supremeId) {
    m_selectedSupremeId = supremeId;
}

void SupremeConsciousnessPanel::SelectAwarenessSupreme(const std::string& awarenessId) {
    m_selectedAwarenessId = awarenessId;
}

void SupremeConsciousnessPanel::SelectCognitionSupreme(const std::string& cognitionId) {
    m_selectedCognitionId = cognitionId;
}

void SupremeConsciousnessPanel::SelectPerceptionSupreme(const std::string& perceptionId) {
    m_selectedPerceptionId = perceptionId;
}

void SupremeConsciousnessPanel::SelectUnderstandingSupreme(const std::string& understandingId) {
    m_selectedUnderstandingId = understandingId;
}

void SupremeConsciousnessPanel::SelectWisdomSupreme(const std::string& wisdomId) {
    m_selectedWisdomId = wisdomId;
}

void SupremeConsciousnessPanel::SelectKnowledgeSupreme(const std::string& knowledgeId) {
    m_selectedKnowledgeId = knowledgeId;
}

void SupremeConsciousnessPanel::CreateNewSupremeConsciousnessStructure() {
    if (std::strlen(m_newSupremeName) > 0) {
        SupremeConsciousness::SupremeConsciousnessEngine::CreateSupremeConsciousnessStructure(m_newSupremeName);
        std::memset(m_newSupremeName, 0, sizeof(m_newSupremeName));
    }
}

void SupremeConsciousnessPanel::CreateNewAwarenessSupreme() {
    if (std::strlen(m_newAwarenessName) > 0) {
        SupremeConsciousness::SupremeConsciousnessEngine::CreateAwarenessSupreme(m_newAwarenessName);
        std::memset(m_newAwarenessName, 0, sizeof(m_newAwarenessName));
    }
}

void SupremeConsciousnessPanel::CreateNewCognitionSupreme() {
    if (std::strlen(m_newCognitionName) > 0) {
        SupremeConsciousness::SupremeConsciousnessEngine::CreateCognitionSupreme(m_newCognitionName);
        std::memset(m_newCognitionName, 0, sizeof(m_newCognitionName));
    }
}

void SupremeConsciousnessPanel::CreateNewPerceptionSupreme() {
    if (std::strlen(m_newPerceptionName) > 0) {
        SupremeConsciousness::SupremeConsciousnessEngine::CreatePerceptionSupreme(m_newPerceptionName);
        std::memset(m_newPerceptionName, 0, sizeof(m_newPerceptionName));
    }
}

void SupremeConsciousnessPanel::CreateNewUnderstandingSupreme() {
    if (std::strlen(m_newUnderstandingName) > 0) {
        SupremeConsciousness::SupremeConsciousnessEngine::CreateUnderstandingSupreme(m_newUnderstandingName);
        std::memset(m_newUnderstandingName, 0, sizeof(m_newUnderstandingName));
    }
}

void SupremeConsciousnessPanel::CreateNewWisdomSupreme() {
    if (std::strlen(m_newWisdomName) > 0) {
        SupremeConsciousness::SupremeConsciousnessEngine::CreateWisdomSupreme(m_newWisdomName);
        std::memset(m_newWisdomName, 0, sizeof(m_newWisdomName));
    }
}

void SupremeConsciousnessPanel::CreateNewKnowledgeSupreme() {
    if (std::strlen(m_newKnowledgeName) > 0) {
        SupremeConsciousness::SupremeConsciousnessEngine::CreateKnowledgeSupreme(m_newKnowledgeName);
        std::memset(m_newKnowledgeName, 0, sizeof(m_newKnowledgeName));
    }
}

void SupremeConsciousnessPanel::ClearInputBuffers() {
    std::memset(m_newSupremeName, 0, sizeof(m_newSupremeName));
    std::memset(m_newAwarenessName, 0, sizeof(m_newAwarenessName));
    std::memset(m_newCognitionName, 0, sizeof(m_newCognitionName));
    std::memset(m_newPerceptionName, 0, sizeof(m_newPerceptionName));
    std::memset(m_newUnderstandingName, 0, sizeof(m_newUnderstandingName));
    std::memset(m_newWisdomName, 0, sizeof(m_newWisdomName));
    std::memset(m_newKnowledgeName, 0, sizeof(m_newKnowledgeName));
}

bool SupremeConsciousnessPanel::FilterMatches(const std::string& text) const {
    if (std::strlen(m_filterBuffer) == 0) return true;
    return text.find(m_filterBuffer) != std::string::npos;
}

void SupremeConsciousnessPanel::DrawProgressBar(float value, const ImVec4& color) {
    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color);
    ImGui::ProgressBar(value, ImVec2(-1, 0), "");
    ImGui::PopStyleColor();
}

void SupremeConsciousnessPanel::DrawMetric(const char* label, float value, const char* format) {
    ImGui::Text("%s: ", label);
    ImGui::SameLine();
    ImGui::Text(format, value);
}

// Action handlers
void SupremeConsciousnessPanel::OnExpandSupremeConsciousness(const std::string& supremeId) {
    SupremeConsciousness::SupremeConsciousnessEngine::ExpandSupremeConsciousness(supremeId);
}

void SupremeConsciousnessPanel::OnAmplifyAwareness(const std::string& supremeId) {
    SupremeConsciousness::SupremeConsciousnessEngine::AmplifyAwareness(supremeId);
}

void SupremeConsciousnessPanel::OnIncreaseCognition(const std::string& supremeId) {
    SupremeConsciousness::SupremeConsciousnessEngine::IncreaseCognition(supremeId);
}

void SupremeConsciousnessPanel::OnEnhancePerception(const std::string& supremeId) {
    SupremeConsciousness::SupremeConsciousnessEngine::EnhancePerception(supremeId);
}

void SupremeConsciousnessPanel::OnDeepenUnderstanding(const std::string& supremeId) {
    SupremeConsciousness::SupremeConsciousnessEngine::DeepenUnderstanding(supremeId);
}

void SupremeConsciousnessPanel::OnCultivateWisdom(const std::string& supremeId) {
    SupremeConsciousness::SupremeConsciousnessEngine::CultivateWisdom(supremeId);
}

void SupremeConsciousnessPanel::OnAccumulateKnowledge(const std::string& supremeId) {
    SupremeConsciousness::SupremeConsciousnessEngine::AccumulateKnowledge(supremeId);
}

void SupremeConsciousnessPanel::OnIntensifyAwarenessSupreme(const std::string& awarenessId) {
    SupremeConsciousness::SupremeConsciousnessEngine::IntensifyAwarenessSupreme(awarenessId);
}

void SupremeConsciousnessPanel::OnBroadenAwarenessSupreme(const std::string& awarenessId) {
    SupremeConsciousness::SupremeConsciousnessEngine::BroadenAwarenessSupreme(awarenessId);
}

void SupremeConsciousnessPanel::OnDeclareAwarenessSupreme(const std::string& awarenessId) {
    SupremeConsciousness::SupremeConsciousnessEngine::DeclareAwarenessSupreme(awarenessId);
}

void SupremeConsciousnessPanel::OnSharpenCognitionSupreme(const std::string& cognitionId) {
    SupremeConsciousness::SupremeConsciousnessEngine::SharpenCognitionSupreme(cognitionId);
}

void SupremeConsciousnessPanel::OnExpandCognitionSupreme(const std::string& cognitionId) {
    SupremeConsciousness::SupremeConsciousnessEngine::ExpandCognitionSupreme(cognitionId);
}

void SupremeConsciousnessPanel::OnDeclareCognitionSupreme(const std::string& cognitionId) {
    SupremeConsciousness::SupremeConsciousnessEngine::DeclareCognitionSupreme(cognitionId);
}

void SupremeConsciousnessPanel::OnRefinePerceptionSupreme(const std::string& perceptionId) {
    SupremeConsciousness::SupremeConsciousnessEngine::RefinePerceptionSupreme(perceptionId);
}

void SupremeConsciousnessPanel::OnHeightenPerceptionSupreme(const std::string& perceptionId) {
    SupremeConsciousness::SupremeConsciousnessEngine::HeightenPerceptionSupreme(perceptionId);
}

void SupremeConsciousnessPanel::OnDeclarePerceptionSupreme(const std::string& perceptionId) {
    SupremeConsciousness::SupremeConsciousnessEngine::DeclarePerceptionSupreme(perceptionId);
}

void SupremeConsciousnessPanel::OnDeepenUnderstandingSupreme(const std::string& understandingId) {
    SupremeConsciousness::SupremeConsciousnessEngine::DeepenUnderstandingSupreme(understandingId);
}

void SupremeConsciousnessPanel::OnClarifyUnderstandingSupreme(const std::string& understandingId) {
    SupremeConsciousness::SupremeConsciousnessEngine::ClarifyUnderstandingSupreme(understandingId);
}

void SupremeConsciousnessPanel::OnDeclareUnderstandingSupreme(const std::string& understandingId) {
    SupremeConsciousness::SupremeConsciousnessEngine::DeclareUnderstandingSupreme(understandingId);
}

void SupremeConsciousnessPanel::OnCultivateWisdomSupreme(const std::string& wisdomId) {
    SupremeConsciousness::SupremeConsciousnessEngine::CultivateWisdomSupreme(wisdomId);
}

void SupremeConsciousnessPanel::OnApplyWisdomSupreme(const std::string& wisdomId) {
    SupremeConsciousness::SupremeConsciousnessEngine::ApplyWisdomSupreme(wisdomId);
}

void SupremeConsciousnessPanel::OnDeclareWisdomSupreme(const std::string& wisdomId) {
    SupremeConsciousness::SupremeConsciousnessEngine::DeclareWisdomSupreme(wisdomId);
}

void SupremeConsciousnessPanel::OnAccumulateKnowledgeSupreme(const std::string& knowledgeId) {
    SupremeConsciousness::SupremeConsciousnessEngine::AccumulateKnowledgeSupreme(knowledgeId);
}

void SupremeConsciousnessPanel::OnOrganizeKnowledgeSupreme(const std::string& knowledgeId) {
    SupremeConsciousness::SupremeConsciousnessEngine::OrganizeKnowledgeSupreme(knowledgeId);
}

void SupremeConsciousnessPanel::OnDeclareKnowledgeSupreme(const std::string& knowledgeId) {
    SupremeConsciousness::SupremeConsciousnessEngine::DeclareKnowledgeSupreme(knowledgeId);
}

} // namespace IDE
