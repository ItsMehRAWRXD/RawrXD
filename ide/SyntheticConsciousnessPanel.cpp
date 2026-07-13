#include "ide/SyntheticConsciousnessPanel.hpp"
#include "synthetic/SyntheticConsciousnessEngine.hpp"
#include "synthetic/SyntheticConsciousnessLoop.hpp"
#include <imgui.h>
#include <algorithm>

namespace Synthetic {

SyntheticConsciousnessPanel::SyntheticConsciousnessPanel()
    : m_visible(false)
    , m_initialized(false)
    , m_loop(nullptr)
{
    m_currentMetrics = nlohmann::json::object();
}

SyntheticConsciousnessPanel::~SyntheticConsciousnessPanel() {
    Shutdown();
}

void SyntheticConsciousnessPanel::Initialize() {
    if (m_initialized) return;
    SyntheticConsciousnessEngine::Init();
    m_loop = new SyntheticConsciousnessLoop();
    m_loop->RegisterTickCallback([this]() { OnTick(); });
    m_loop->RegisterSyntheticCallback([this](const std::string& event) { OnSyntheticEvent(event); });
    m_initialized = true;
}

void SyntheticConsciousnessPanel::Shutdown() {
    if (!m_initialized) return;
    if (m_loop) {
        m_loop->Stop();
        delete m_loop;
        m_loop = nullptr;
    }
    SyntheticConsciousnessEngine::Shutdown();
    m_initialized = false;
}

void SyntheticConsciousnessPanel::Render(const char* title) {
    if (!m_visible || !m_initialized) return;

    ImGui::SetNextWindowSize(ImVec2(900, 700), ImGuiCond_FirstUseEver);
    if (ImGui::Begin(title, &m_visible)) {
        if (ImGui::Button(m_loop->IsRunning() ? "Stop Loop" : "Start Loop")) {
            if (m_loop->IsRunning()) {
                m_loop->Stop();
                m_state.loopRunning = false;
            } else {
                m_loop->Start();
                m_state.loopRunning = true;
            }
        }
        ImGui::SameLine();
        ImGui::SliderInt("Tick Rate", &m_state.tickRate, 1, 120);
        m_loop->SetTickRate(m_state.tickRate);
        ImGui::SameLine();
        ImGui::Text("Ticks: %lld", m_loop->GetTickCount());

        if (ImGui::BeginTabBar("SyntheticConsciousnessTabs")) {
            if (m_state.showSyntheticMinds && ImGui::BeginTabItem("Synthetic Minds")) {
                RenderSyntheticMindsTab();
                ImGui::EndTabItem();
            }
            if (m_state.showEmulationLayers && ImGui::BeginTabItem("Emulation Layers")) {
                RenderEmulationLayersTab();
                ImGui::EndTabItem();
            }
            if (m_state.showCognitiveTemplates && ImGui::BeginTabItem("Cognitive Templates")) {
                RenderCognitiveTemplatesTab();
                ImGui::EndTabItem();
            }
            if (m_state.showConsciousnessForks && ImGui::BeginTabItem("Consciousness Forks")) {
                RenderConsciousnessForksTab();
                ImGui::EndTabItem();
            }
            if (m_state.showSubstrateBridges && ImGui::BeginTabItem("Substrate Bridges")) {
                RenderSubstrateBridgesTab();
                ImGui::EndTabItem();
            }
            if (m_state.showMetrics && ImGui::BeginTabItem("Metrics")) {
                RenderMetricsTab();
                ImGui::EndTabItem();
            }
            if (m_state.showEventLog && ImGui::BeginTabItem("Event Log")) {
                RenderEventLogTab();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::End();
}

bool SyntheticConsciousnessPanel::IsVisible() const {
    return m_visible;
}

void SyntheticConsciousnessPanel::SetVisible(bool visible) {
    m_visible = visible;
}

void SyntheticConsciousnessPanel::ToggleVisibility() {
    m_visible = !m_visible;
}

void SyntheticConsciousnessPanel::OnTick() {
    UpdateMetrics();
}

void SyntheticConsciousnessPanel::OnSyntheticEvent(const std::string& event) {
    m_state.eventLog.push_back(event);
    if (m_state.eventLog.size() > 100) {
        m_state.eventLog.erase(m_state.eventLog.begin());
    }
}

SyntheticConsciousnessPanelState& SyntheticConsciousnessPanel::GetState() {
    return m_state;
}

void SyntheticConsciousnessPanel::RenderSyntheticMindsTab() {
    ImGui::Text("Instantiate New Synthetic Mind:");
    ImGui::InputText("Mind Name", m_state.newMindName, sizeof(m_state.newMindName));
    ImGui::InputText("Substrate", m_state.selectedSubstrate, sizeof(m_state.selectedSubstrate));
    if (ImGui::Button("Instantiate")) {
        if (strlen(m_state.newMindName) > 0 && strlen(m_state.selectedSubstrate) > 0) {
            SyntheticConsciousnessEngine::InstantiateMind(m_state.newMindName, m_state.selectedSubstrate);
            m_state.newMindName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Synthetic Minds:");
    auto minds = SyntheticConsciousnessEngine::GetAllMinds();
    if (ImGui::BeginTable("MindsTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Substrate");
        ImGui::TableSetupColumn("Complexity");
        ImGui::TableSetupColumn("Autonomy");
        ImGui::TableHeadersRow();
        for (const auto& mind : minds) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", mind.mindId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", mind.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", mind.substrate.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", mind.complexity);
            ImGui::TableNextColumn(); ImGui::Text("%.2f", mind.autonomy);
        }
        ImGui::EndTable();
    }
}

void SyntheticConsciousnessPanel::RenderEmulationLayersTab() {
    ImGui::Text("Create Emulation Layer:");
    ImGui::InputText("Layer Name", m_state.newLayerName, sizeof(m_state.newLayerName));
    ImGui::InputText("Target System", m_state.selectedTarget, sizeof(m_state.selectedTarget));
    if (ImGui::Button("Create")) {
        if (strlen(m_state.newLayerName) > 0 && strlen(m_state.selectedTarget) > 0) {
            SyntheticConsciousnessEngine::CreateEmulationLayer(m_state.newLayerName, m_state.selectedTarget);
            m_state.newLayerName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Emulation Layers:");
    auto layers = SyntheticConsciousnessEngine::GetAllLayers();
    if (ImGui::BeginTable("LayersTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Target");
        ImGui::TableSetupColumn("Fidelity");
        ImGui::TableSetupColumn("Active");
        ImGui::TableHeadersRow();
        for (const auto& layer : layers) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", layer.layerId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", layer.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", layer.targetSystem.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", layer.fidelity);
            ImGui::TableNextColumn(); ImGui::Text("%s", layer.isActive ? "Yes" : "No");
        }
        ImGui::EndTable();
    }
}

void SyntheticConsciousnessPanel::RenderCognitiveTemplatesTab() {
    ImGui::Text("Design Cognitive Template:");
    ImGui::InputText("Template Name", m_state.newTemplateName, sizeof(m_state.newTemplateName));
    ImGui::InputText("Template Type", m_state.selectedType, sizeof(m_state.selectedType));
    if (ImGui::Button("Design")) {
        if (strlen(m_state.newTemplateName) > 0 && strlen(m_state.selectedType) > 0) {
            SyntheticConsciousnessEngine::DesignTemplate(m_state.newTemplateName, m_state.selectedType);
            m_state.newTemplateName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Designed Cognitive Templates:");
    auto templates = SyntheticConsciousnessEngine::GetAllTemplates();
    if (ImGui::BeginTable("TemplatesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Adaptability");
        ImGui::TableHeadersRow();
        for (const auto& ct : templates) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", ct.templateId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", ct.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", ct.templateType.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", ct.adaptability);
        }
        ImGui::EndTable();
    }
}

void SyntheticConsciousnessPanel::RenderConsciousnessForksTab() {
    ImGui::Text("Active Consciousness Forks:");
    auto forks = SyntheticConsciousnessEngine::GetAllForks();
    if (ImGui::BeginTable("ForksTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Divergence");
        ImGui::TableSetupColumn("Merged");
        ImGui::TableHeadersRow();
        for (const auto& fork : forks) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", fork.forkId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", fork.sourceMind.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", fork.forkType.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", fork.divergence);
            ImGui::TableNextColumn(); ImGui::Text("%s", fork.isMerged ? "Yes" : "No");
        }
        ImGui::EndTable();
    }
}

void SyntheticConsciousnessPanel::RenderSubstrateBridgesTab() {
    ImGui::Text("Active Substrate Bridges:");
    auto bridges = SyntheticConsciousnessEngine::GetAllBridges();
    if (ImGui::BeginTable("BridgesTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("Target");
        ImGui::TableSetupColumn("Accuracy");
        ImGui::TableSetupColumn("Operational");
        ImGui::TableHeadersRow();
        for (const auto& bridge : bridges) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", bridge.bridgeId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", bridge.sourceSubstrate.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", bridge.targetSubstrate.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", bridge.translationAccuracy);
            ImGui::TableNextColumn(); ImGui::Text("%s", bridge.isOperational ? "Yes" : "No");
        }
        ImGui::EndTable();
    }
}

void SyntheticConsciousnessPanel::RenderMetricsTab() {
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    ImGui::Text("Synthetic Metrics:");
    if (m_currentMetrics.contains("mindCount")) {
        ImGui::Text("Synthetic Minds: %d", m_currentMetrics["mindCount"].get<int>());
        ImGui::Text("Emulation Layers: %d", m_currentMetrics["layerCount"].get<int>());
        ImGui::Text("Cognitive Templates: %d", m_currentMetrics["templateCount"].get<int>());
        ImGui::Text("Consciousness Forks: %d", m_currentMetrics["forkCount"].get<int>());
        ImGui::Text("Substrate Bridges: %d", m_currentMetrics["bridgeCount"].get<int>());
        ImGui::Separator();
        ImGui::Text("Average Complexity: %.3f", m_currentMetrics["averageComplexity"].get<float>());
        ImGui::Text("Total Autonomy: %.3f", m_currentMetrics["totalAutonomy"].get<float>());
        ImGui::Text("Active Forks: %d", m_currentMetrics["activeForks"].get<int>());
        ImGui::Text("Tick Count: %lld", m_currentMetrics["tickCount"].get<int64_t>());
    }
}

void SyntheticConsciousnessPanel::RenderEventLogTab() {
    ImGui::Text("Recent Synthetic Events:");
    ImGui::BeginChild("EventLog", ImVec2(0, 400), true);
    for (const auto& event : m_state.eventLog) {
        ImGui::Text("%s", event.c_str());
    }
    ImGui::EndChild();
    if (ImGui::Button("Clear Log")) {
        m_state.eventLog.clear();
    }
}

void SyntheticConsciousnessPanel::UpdateMetrics() {
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    m_currentMetrics = SyntheticConsciousnessEngine::GetSyntheticMetrics();
}

} // namespace Synthetic
